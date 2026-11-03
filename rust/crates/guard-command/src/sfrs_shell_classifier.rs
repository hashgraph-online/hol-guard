//! `secret_file_request_services/shell_request_classifier.py`:
//! `_destructive_shell_tool_action_request` and
//! `_classify_shell_tool_action_request`.

// Consumed by the dispatcher wiring.
#![allow(dead_code)]

use std::path::Path;

use serde_json::Value;

use crate::benign_request_api::ToolActionControls;
use crate::codex_output_env::Ctx;
use crate::codex_output_py::py_strip;
use crate::command_evaluation::CommandDecisionFloor;
use crate::command_model::{parse_shell_command, CanonicalCommand};
use crate::extension_control::{resolve_extension_controls, ControlSurface};
use crate::github_capability_contract::{
    github_capability_contract, GitHubCommandAssessment, GitHubCommandCapability,
};
use crate::github_capability_interaction::{
    github_capability_action_class, github_capability_requires_confirmation,
};
use crate::native_command_catalog::packaged_command_catalog;
use crate::sfrs_constants::SHELL_TOOL_NAMES;
use crate::sfrs_destructive_classifier::{
    looks_destructive_shell_command, looks_destructive_shell_command_in,
};
use crate::sfrs_dispatcher_request::{
    effective_cwd_texts, model_context, DispatchError, NativeEvaluationView, ToolActionRequestMatch,
};
use crate::sfrs_gh_body_safety::{
    gh_pr_create_uses_safe_static_body_file, gh_pr_edit_uses_safe_static_body_file,
};
use crate::sfrs_gh_service::classify_github_shell_capabilities;
use crate::sfrs_interpreter_scripts::is_python_interpreter_command;
use crate::sfrs_interpreter_trust::pytest_config_assessment_for_command;
use crate::sfrs_pytest_config::PytestConfigAssessment;
use crate::sfrs_pytest_target::shell_command_targets_pytest;
use crate::sfrs_shell_classifier_context::{
    apply_bounded_source_edit, apply_developer_context, apply_github_home_context,
    apply_home_risk_context, Env, Selection,
};
use crate::sfrs_shell_initial_risk::{
    initial_shell_risk_match, InteractionMatch, RiskInputs, LOCAL_SECRET_READ_ACTION_CLASS,
};
use crate::sfrs_source_edit_context::shell_execution_context_validation_reason;
use crate::shell_execution_context::ShellExecutionContext;
use crate::shell_execution_context_support::SHELL_CWD_UNRESOLVED_PARENT_SHELL;

const PYTEST_RESTRICTED_PROFILE_VERSION: &str = "pytest-restricted-v1";
const PYTEST_PROFILE_REASON_CODE: &str = "pytest_restricted_profile_required";
const UNSAFE_PYTEST_REASON: &str = "Guard found execution-affecting pytest configuration or could not inspect the selected pytest configuration completely. Keep plugin/output/config overrides inside the restricted pytest profile; repair or remove malformed, missing, unreadable, oversized, or unsafe config inputs before retrying.";
const DESTRUCTIVE_REASON: &str = "Guard treats destructive shell writes and delete operations as sensitive because they can mutate the local machine before the user confirms the action.";
const PYTEST_REASON: &str = "pytest_restricted_profile_required: Pytest collection imports repository-controlled tests, conftest.py files, and plugins. Run the exact pytest argv through `hol-guard pytest-contained -- python3 -m pytest <args>` (or `-- pytest <args>`; add `--workspace <project root>` when not already in it); Guard will not launch pytest when the required operating-system sandbox is unavailable.";

/// The keyword arguments of the two Python entry points.
pub(crate) struct ShellClassifyInputs<'a> {
    pub tool_name: &'a str,
    pub normalized_tool_name: &'a str,
    pub command_text: &'a str,
    pub cwd: Option<&'a Path>,
    pub home_dir: Option<&'a Path>,
    pub canonical_command: Option<&'a CanonicalCommand>,
    pub raw_command_text: Option<&'a str>,
    pub execution_context: Option<&'a ShellExecutionContext>,
    pub raw_execution_context: Option<&'a ShellExecutionContext>,
    pub native_evaluation: Option<&'a NativeEvaluationView>,
    pub controls: Option<&'a ToolActionControls>,
    pub ctx: &'a Ctx<'a>,
}

type Outcome = Result<Option<ToolActionRequestMatch>, DispatchError>;

fn parse_canonical(inputs: &ShellClassifyInputs) -> Result<CanonicalCommand, DispatchError> {
    if let Some(command) = inputs.canonical_command {
        return Ok(command.clone());
    }
    if py_strip(inputs.command_text).is_empty() {
        return Err(DispatchError::new("Command text cannot be empty"));
    }
    Ok(parse_shell_command(
        inputs.command_text,
        inputs.cwd,
        inputs.home_dir,
        "posix",
        "shell_string",
        "guard-shell",
        true,
    ))
}

/// `_destructive_shell_tool_action_request`.
pub(crate) fn destructive_shell_tool_action_request(inputs: &ShellClassifyInputs) -> Outcome {
    let result = classify_shell_tool_action_request(inputs)?;
    if result.is_some()
        || !SHELL_TOOL_NAMES.contains(&inputs.normalized_tool_name)
        || !cfg!(windows)
    {
        return Ok(result);
    }
    let canonical = parse_canonical(inputs)?;
    Ok(windows_interpreter_floor(inputs, &canonical))
}

/// The `os.name == "nt"` floor: a compound Python launch has no Windows host
/// ACL proof.
pub(crate) fn windows_interpreter_floor(
    inputs: &ShellClassifyInputs,
    canonical: &CanonicalCommand,
) -> Option<ToolActionRequestMatch> {
    let python_launch = canonical
        .segments
        .iter()
        .any(|segment| is_python_interpreter_command(segment.executable.as_deref().unwrap_or("")));
    let allowed = inputs
        .native_evaluation
        .is_none_or(|native| native.minimum_action == CommandDecisionFloor::Allow);
    if canonical.segments.len() <= 1 || !python_launch || !allowed {
        return None;
    }
    let raw_text = inputs
        .raw_command_text
        .filter(|raw| !raw.is_empty())
        .unwrap_or(inputs.command_text);
    let selected = inputs.raw_execution_context.or(inputs.execution_context);
    let (cwd, home) = (
        inputs.cwd.map(crate::codex_output_source_paths::py_path),
        inputs
            .home_dir
            .map(crate::codex_output_source_paths::py_path),
    );
    let identity_inputs = crate::sfrs_interpreter_identity::IdentityInputs {
        cwd: cwd.as_ref(),
        home_dir: home.as_ref(),
        environment: None,
        workspace_root: None,
        execution_context: selected,
    };
    Some(ToolActionRequestMatch {
        canonical_command: Some(canonical.clone()),
        guard_default_action: Some("require-reapproval".to_owned()),
        reason_code: Some("interpreter_host_binding_unverified".to_owned()),
        interpreter_executable_identities:
            crate::sfrs_interpreter_identity::python_interpreter_executable_identities(
                raw_text,
                &identity_inputs,
                0,
                inputs.ctx,
            ),
        ..ToolActionRequestMatch::new(
            inputs.tool_name,
            inputs.normalized_tool_name,
            inputs.command_text,
            "unverified compound interpreter host",
            "Guard requires review because this compound Python launch has no Windows host ACL proof.",
        )
    })
}

/// What the native evaluation contributes: an early `None`, or the extension
/// interaction that outranks the legacy checks.
enum NativeVerdict {
    Benign,
    Interaction(Option<InteractionMatch>),
}

fn native_verdict(
    native: Option<&NativeEvaluationView>,
    canonical: &CanonicalCommand,
) -> Result<NativeVerdict, DispatchError> {
    let Some(native) = native else {
        return Ok(NativeVerdict::Interaction(None));
    };
    if native.security_identity != canonical.security_identity() {
        return Err(DispatchError::new(
            "native command evaluation does not match the classified command",
        ));
    }
    let explicitly_benign = native.has_reason("native.explicit-benign");
    let allow_floor_only = !native.match_default_modes.is_empty()
        && native
            .match_default_modes
            .iter()
            .all(|mode| mode == "disabled");
    let allows = native.minimum_action == CommandDecisionFloor::Allow;
    let enabled = !native.explicitly_enabled_permission_ids.is_empty();
    if allows && (explicitly_benign || allow_floor_only) && !enabled {
        return Ok(NativeVerdict::Benign);
    }
    // A rule left at its disabled default contributes only an allow floor, so
    // a review floor beside it comes from non-extension factors such as a
    // verified-read proof requirement. The legacy checks below classify those
    // exactly as on a device without an enrolled authority; naming the rule's
    // action class would turn every default-disabled match into an approval.
    let disabled_rules_review =
        allow_floor_only && !enabled && native.minimum_action != CommandDecisionFloor::Block;
    let interaction = match (&native.controlling_action_class, &native.controlling_reason) {
        (Some(action_class), Some(reason))
            if !native.match_default_modes.is_empty()
                && (!allows || enabled)
                && !disabled_rules_review =>
        {
            Some(InteractionMatch {
                action_class: action_class.clone(),
                reason: reason.clone(),
            })
        }
        _ => None,
    };
    Ok(NativeVerdict::Interaction(interaction))
}

/// The pytest facts every pytest-aware request copies.
struct PytestFacts {
    requested: bool,
    assessment: PytestConfigAssessment,
    sources: Vec<String>,
}

impl PytestFacts {
    fn apply(&self, request: ToolActionRequestMatch) -> ToolActionRequestMatch {
        ToolActionRequestMatch {
            guard_default_action: self.requested.then(|| "sandbox-required".to_owned()),
            reason_code: self
                .requested
                .then(|| PYTEST_PROFILE_REASON_CODE.to_owned()),
            restricted_profile_version: self
                .requested
                .then(|| PYTEST_RESTRICTED_PROFILE_VERSION.to_owned()),
            pytest_config_identity_sha256: self.assessment.identity_sha256.clone(),
            pytest_config_sources: self.sources.clone(),
            pytest_config_reason_codes: self.assessment.reason_codes.clone(),
            ..request
        }
    }
}

fn proposal_control_block(controls: Option<&ToolActionControls>) -> bool {
    let (Some(controls), Ok(catalog)) = (controls, packaged_command_catalog()) else {
        return false;
    };
    let Some(permission) = catalog.permission_for_typed_capability("propose_remote") else {
        return false;
    };
    resolve_extension_controls(
        &controls.layers,
        Some(&*catalog),
        &[permission.extension_id.clone()],
        &[permission.permission_id.clone()],
        ControlSurface::CommandEvaluation,
        &[],
        controls.authority_failure,
    )
    .blocked
}

fn safe_body_file(check: fn(&str, Option<&Path>, Option<&Path>, &Ctx) -> bool, env: &Env) -> bool {
    check(env.detection, env.cwd, env.home_dir, env.ctx)
        && env
            .differing_raw()
            .is_none_or(|raw| check(raw, env.cwd, env.home_dir, env.ctx))
}

fn starts_with_source(context: &ShellExecutionContext) -> bool {
    context
        .segments
        .first()
        .and_then(|segment| segment.tokens.first())
        .is_some_and(|token| token == "source" || token == ".")
}

/// `_classify_shell_tool_action_request`.
pub(crate) fn classify_shell_tool_action_request(inputs: &ShellClassifyInputs) -> Outcome {
    if !SHELL_TOOL_NAMES.contains(&inputs.normalized_tool_name) {
        return Ok(None);
    }
    let (cwd, home_dir, ctx) = (inputs.cwd, inputs.home_dir, inputs.ctx);
    let canonical = parse_canonical(inputs)?;
    let detection = inputs.command_text;
    let env = Env {
        detection,
        raw: inputs.raw_command_text,
        cwd,
        home_dir,
        ctx,
    };
    let execution_context = inputs
        .execution_context
        .cloned()
        .unwrap_or_else(|| model_context(ctx, detection, cwd, cwd, home_dir));
    let requested = shell_command_targets_pytest(detection, 0);
    let assessment = if requested {
        pytest_config_assessment_for_command(detection, cwd, &execution_context)
    } else {
        PytestConfigAssessment {
            complete: true,
            ..PytestConfigAssessment::default()
        }
    };
    let pytest = PytestFacts {
        requested,
        sources: assessment
            .results
            .iter()
            .map(|result| result.source_path.clone())
            .collect(),
        assessment,
    };
    let identities = env.identities(cwd, &execution_context, inputs.raw_execution_context);
    let interaction = match native_verdict(inputs.native_evaluation, &canonical)? {
        NativeVerdict::Benign => return Ok(None),
        NativeVerdict::Interaction(interaction) => interaction,
    };
    let (handled, initial_risk) = initial_shell_risk_match(
        &RiskInputs {
            tool_name: inputs.tool_name,
            normalized_tool_name: inputs.normalized_tool_name,
            command_text: detection,
            detection_command_text: detection,
            raw_command_text: inputs.raw_command_text,
            cwd,
            home_dir,
            canonical_command: &canonical,
            interpreter_executable_identities: &identities,
            ctx,
        },
        interaction.as_ref(),
    );
    if handled {
        return Ok(initial_risk);
    }
    let mut selection = Selection {
        execution_context,
        raw_execution_context: inputs.raw_execution_context.cloned(),
        identities,
        bounded_source_edit: false,
    };
    apply_developer_context(&env, &mut selection);
    let github = classify_github_shell_capabilities(env.raw_or_detection(), home_dir, ctx);
    apply_home_risk_context(&env, &mut selection);
    apply_github_home_context(&env, &mut selection, github.as_ref());
    apply_bounded_source_edit(&env, &mut selection);
    finish(
        inputs,
        &env,
        &canonical,
        &selection,
        &pytest,
        github.as_ref(),
        initial_risk,
    )
}

fn finish(
    inputs: &ShellClassifyInputs,
    env: &Env,
    canonical: &CanonicalCommand,
    selection: &Selection,
    pytest: &PytestFacts,
    github: Option<&GitHubCommandAssessment>,
    initial_risk: Option<ToolActionRequestMatch>,
) -> Outcome {
    let execution = &selection.execution_context;
    let reason = shell_execution_context_validation_reason(execution);
    if initial_risk
        .as_ref()
        .is_some_and(|risk| risk.action_class == LOCAL_SECRET_READ_ACTION_CLASS)
        && reason.as_deref() == Some(SHELL_CWD_UNRESOLVED_PARENT_SHELL)
        && starts_with_source(execution)
    {
        return Ok(initial_risk);
    }
    let make = |action_class: &str, text: &str| ToolActionRequestMatch {
        canonical_command: Some(canonical.clone()),
        interpreter_executable_identities: selection.identities.clone(),
        ..ToolActionRequestMatch::new(
            inputs.tool_name,
            inputs.normalized_tool_name,
            inputs.command_text,
            action_class,
            text,
        )
    };
    if let (true, Some(reason)) = (execution.directory_change_present, &reason) {
        let text = format!(
            "Guard could not prove the working directory for every shell segment and requires one conservative decision before the user confirms execution ({reason}). Use a literal, existing in-workspace directory with deterministic cd/pushd/popd control flow, or run the command from the intended directory."
        );
        return Ok(Some(pytest.apply(ToolActionRequestMatch {
            shell_execution_context_hash: Some(execution.context_hash()),
            shell_execution_context_reason_code: Some(reason.clone()),
            shell_execution_effective_cwds: effective_cwd_texts(execution),
            ..make("unresolved shell execution context", &text)
        })));
    }
    let (cwd, home, ctx, detection) = (inputs.cwd, inputs.home_dir, inputs.ctx, env.detection);
    let raw_context = selection.raw_execution_context.as_ref();
    let detection_destructive =
        looks_destructive_shell_command_in(detection, cwd, home, ctx, execution);
    let raw_destructive = match (env.differing_raw(), raw_context) {
        (Some(raw), Some(raw_context)) => {
            looks_destructive_shell_command_in(raw, cwd, home, ctx, raw_context)
        }
        (Some(raw), None) => looks_destructive_shell_command(raw, cwd, home, ctx),
        _ => false,
    };
    if (detection_destructive || raw_destructive) && !selection.bounded_source_edit {
        let matched = if raw_destructive {
            raw_context.unwrap_or(execution)
        } else {
            execution
        };
        let text = if pytest.requested && pytest.assessment.unsafe_options {
            UNSAFE_PYTEST_REASON
        } else {
            DESTRUCTIVE_REASON
        };
        let directory_change = matched.directory_change_present;
        return Ok(Some(pytest.apply(ToolActionRequestMatch {
            shell_execution_context_hash: directory_change.then(|| matched.context_hash()),
            shell_execution_context_reason_code: matched.reason_code.clone(),
            shell_execution_effective_cwds: if directory_change {
                effective_cwd_texts(matched)
            } else {
                Vec::new()
            },
            ..make("destructive shell command", text)
        })));
    }
    if pytest.requested {
        return Ok(Some(pytest.apply(ToolActionRequestMatch {
            guard_default_action: Some("sandbox-required".to_owned()),
            ..make("pytest repository-code execution", PYTEST_REASON)
        })));
    }
    if safe_body_file(gh_pr_create_uses_safe_static_body_file, env) {
        if !proposal_control_block(inputs.controls) {
            return Ok(None);
        }
        let contract = github_capability_contract(GitHubCommandCapability::ProposeRemote);
        return Ok(Some(make(
            contract
                .action_class
                .unwrap_or("GitHub pull-request proposal command"),
            "Guard extension controls block this GitHub capability.",
        )));
    }
    if safe_body_file(gh_pr_edit_uses_safe_static_body_file, env) {
        return Ok(None);
    }
    if let Some(assessment) = github.filter(|found| github_capability_requires_confirmation(found))
    {
        let action_class = github_capability_action_class(assessment).map_err(DispatchError)?;
        let text = format!(
            "{} Guard requires confirmation because the operation is not a statically proven read-only composition.",
            assessment.detail
        );
        return Ok(Some(make(action_class, &text)));
    }
    let mut trusts: Vec<String> = selection
        .identities
        .iter()
        .filter_map(|evidence| {
            let trust = evidence.get("trust");
            let trusted = matches!(
                trust.and_then(Value::as_str),
                Some("trusted_guard" | "trusted_system")
            );
            (!trusted).then(|| match trust {
                Some(Value::String(text)) if !text.is_empty() => text.clone(),
                Some(Value::Null) | None => "unknown".to_owned(),
                Some(other) => other.to_string(),
            })
        })
        .collect();
    if !trusts.is_empty() {
        trusts.sort();
        trusts.dedup();
        let text = format!(
            "Guard requires review because the Python command resolves through an interpreter path that is not an attested Guard or system runtime ({}). The decision is bound to the raw interpreter token, launch path, symlink chain, executable mode, file identity, and content hash.",
            trusts.join(", ")
        );
        return Ok(Some(ToolActionRequestMatch {
            reason_code: Some("interpreter_identity_untrusted".to_owned()),
            ..make("untrusted Python interpreter", &text)
        }));
    }
    Ok(initial_risk)
}
