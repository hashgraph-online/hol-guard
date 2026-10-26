//! Checks followed by a Git publish, such as
//! `npm test && git add -A && git commit -m x && git push`.
//!
//! The checks run in the workspace sandbox. The trailing Git steps cannot run
//! there (a push needs the network), so the sink runs them outside it, and
//! only after Guard proves them again on their own once the checks have run.
//! Each part is judged as if it were the whole command, so the chain admits
//! nothing its parts would not admit separately.
use crate::pretool::workspace_contained::{admitted_workspace, mark_contained, SHELL_STATE};
use crate::pretool::PathContext;
use crate::{parse_command, CommandModelRequestV1};
use guard_contracts::PreToolResultV1;
use serde_json::Value;

/// The reason a split chain carries. The sink reads it from the receipt to
/// plan the same split, so it must stay an exact constant.
pub(crate) const REASON_TEXT: &str = concat!(
    "HOL Guard runs the checks in this command in a protected workspace sandbox ",
    "(no network, no home access, no PTY or Docker socket), then runs the Git ",
    "steps that follow directly, outside the sandbox, once it proves them again. ",
    "Every program the checks start, including children of an interpreter, runs ",
    "contained and can write only the workspace, $TMPDIR and a private ",
    "scratch $HOME.",
);

const PUBLISHERS: &[&str] = &["git", "gh"];

/// The checks and the Git steps of `text`: the text before and after the
/// `&&` that starts its final run of `git`/`gh` steps, or `None` for any
/// other shape. Classification and the launch plan both split with this.
pub(crate) fn split(text: &str) -> Option<(String, String)> {
    let model = parse_command(&CommandModelRequestV1 {
        command: text.to_owned(),
        dialect: "posix".into(),
        transport: "shell_string".into(),
        extraction_provenance: "pre-tool-generic".into(),
    })
    .ok()?;
    if model.confidence != "exact"
        || model.path_overridden
        || !model.wrapper_chain.is_empty()
        || text.trim() != model.normalized_text
    {
        return None;
    }
    let segments = &model.segments;
    let name = |index: usize| {
        segments[index]
            .executable
            .as_deref()
            .map(crate::pretool::executable_basename)
    };
    let mut start = segments.len();
    while start > 0 && name(start - 1).is_some_and(|name| PUBLISHERS.contains(&name)) {
        start -= 1;
    }
    if start == 0 || start == segments.len() {
        return None;
    }
    // The checks run in their own shell, so a builtin that changes the
    // shell's state, such as `cd` or `export`, would no longer reach the Git
    // steps.
    if (0..start).any(|index| name(index).is_none_or(|name| SHELL_STATE.contains(&name))) {
        return None;
    }
    if (start..segments.len() - 1).any(|index| {
        crate::pretool::worktree_add::separator_between(&model, index, index + 1)
            .as_deref()
            .map(str::trim)
            != Some("&&")
    }) {
        return None;
    }
    let at = segments[start].span.start;
    let head: String = model.normalized_text.chars().take(at).collect();
    let checks = head.trim().strip_suffix("&&")?.trim_end();
    if checks.is_empty() || checks.ends_with(['&', '|', ';']) {
        return None;
    }
    let publish: String = model.normalized_text.chars().skip(at).collect();
    Some((checks.to_owned(), publish.trim().to_owned()))
}

/// The chain as a contained run of its checks followed by its proven Git
/// steps, or `raw` unchanged when either part would not pass on its own.
pub(crate) fn rejudge(
    raw: PreToolResultV1,
    payload: &Value,
    context: PathContext<'_>,
    evaluate: impl Fn(&Value) -> PreToolResultV1,
) -> PreToolResultV1 {
    if raw.minimum_action != "review" || raw.action.sensitive_target || !clean_evidence(&raw) {
        return raw;
    }
    let Some(command) = super::extract_generic_signals(payload)
        .ok()
        .and_then(|signals| signals.command)
    else {
        return raw;
    };
    let Some((checks, publish)) = split(&command) else {
        return raw;
    };
    if !admitted_workspace(context).is_some_and(|workspace| launches(&checks, &workspace)) {
        return raw;
    }
    let judged = |part: &str| {
        let projected = super::payload_with_command(payload, &command, part);
        (projected != *payload).then(|| evaluate(&projected))
    };
    let Some(first) = judged(&checks) else {
        return raw;
    };
    let contained = first.minimum_action == "sandbox-required"
        && first.reason_code == crate::pretool::workspace_contained::REASON;
    if !(contained || allowed(&first)) || !judged(&publish).is_some_and(|second| allowed(&second)) {
        return raw;
    }
    let mut result = raw;
    mark_contained(&mut result);
    result.reason = REASON_TEXT.into();
    result
}

fn allowed(result: &PreToolResultV1) -> bool {
    result.minimum_action == "allow"
        && result.decision == "allow"
        && result.policy_action == "allow"
}

/// The receipt binds the whole chain's extension evidence, so it must be
/// fully characterised: loaded, evaluated and free of uncertain matches.
fn clean_evidence(result: &PreToolResultV1) -> bool {
    result
        .command_extensions
        .as_ref()
        .is_some_and(|extensions| {
            extensions.evaluation_error.is_none()
            && extensions.binding.uncertainty_count == 0
            && extensions
                .observations
                .iter()
                .all(|observation| observation.uncertainty_reasons.is_empty())
            // The receipt carries only the Node package-protection permission.
            && extensions.permission_observations.iter().all(|observation| {
                observation.mcp_tool.is_none()
                    && observation.extension_id == "command.package.node"
                    && observation.permission_id
                        == "command.package.node.permission.package-protection"
                    && observation.uncertainty_reasons.is_empty()
            })
        })
}

/// The sandbox runs the checks exactly as written, with no `git init` split.
#[cfg(unix)]
fn launches(checks: &str, workspace: &std::path::Path) -> bool {
    crate::pretool::workspace_exact_shape(checks, workspace).is_some_and(|shape| {
        shape.bootstrap.is_none() && shape.prefix.is_none() && shape.remainder.is_none()
    })
}

#[cfg(not(unix))]
fn launches(_checks: &str, _workspace: &std::path::Path) -> bool {
    false
}

#[cfg(test)]
#[path = "contained_publish_tests.rs"]
mod tests;
