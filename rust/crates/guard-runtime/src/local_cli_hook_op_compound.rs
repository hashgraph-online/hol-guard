//! Compound shell commands that launch one local CLI: the grant read after a
//! `cd`, and the changed-script connector lookup.
use super::*;

/// `refined` naming the changed script a reviewed compound command waits on.
/// Only a review with no single CLI launch, no package script and no
/// connector of its own takes one.
pub(super) fn with_changed_connector(
    request: &LocalCliHookRequestV1,
    package: &Package,
    no_single_launch: bool,
    mut refined: Refined,
) -> Refined {
    if no_single_launch
        && refined.action == "review"
        && refined.connector.is_none()
        && matches!(package, Ok(None))
    {
        refined.connector = changed_connector(request);
    }
    refined
}

/// The connector a reviewed compound command waits on: the one CLI it
/// launches, when the user allowed only an earlier version of that CLI. The
/// grant step reads a single invocation alone, so without this a changed
/// script run as `cd dir && ./script` or `./script | tail` was an ordinary
/// review whose Always allow saved only that exact text. Naming the connector
/// changes no action: the review stays a review, and only its card offers the
/// new version. A command that launches more than one CLI names none.
fn changed_connector(request: &LocalCliHookRequestV1) -> Option<Value> {
    // A changed-script card must not obscure a review for an independent risk.
    // The already-Review action is unchanged regardless of this proof.
    if !crate::connector_setup::grant_lifts(request.current_reason_code.as_deref()) {
        return None;
    }
    let records = unlisted(request, true).ok()?;
    let first = records.first()?;
    if records.iter().any(|record| record.cli_id != first.cli_id) {
        return None;
    }
    let record = records.into_iter().next()?;
    let launch = Launch {
        cli_id: record.cli_id,
        identity_hash: record.identity_hash,
        name: record.name,
        kind: record.kind,
        runner: record.runner,
        source: record.identity_source,
    };
    crate::connector_setup::for_changed_launch(request, &launch)
}

/// The grant answer for `cd DIR && COMMAND`, read as COMMAND launched in DIR.
///
/// `cd` only selects the directory the next command starts in, and `&&` runs
/// nothing after a failed change, so the pair launches exactly what COMMAND
/// launches from DIR. The user's decision on that CLI answers the compound the
/// way it answers COMMAND alone: an allowed CLI runs, a blocked one is blocked,
/// and an undecided one names its connector. Without this an allowed script
/// run as `cd repo && script -m "..."` was an ordinary review whose Always
/// allow saved only that exact text, so every new argument asked again.
///
/// Only an action that already runs, or a review due to non-recognition, is
/// read this way. Any other review keeps its own risk signal, and a command
/// the workspace sandbox bounds keeps its single-invocation route.
pub(super) fn grant_after_cd(request: &LocalCliHookRequestV1) -> Option<contained::Answer> {
    if !matches!(request.current_action.as_str(), "allow" | "warn" | "review")
        || !crate::connector_setup::grant_lifts(request.current_reason_code.as_deref())
    {
        return None;
    }
    let launched = after_cd(request)?;
    let package = checked_package(&launched).ok()?;
    match grant(&launched, &package) {
        answer @ Ok((_, Some(_), _)) => Some(answer),
        _ => None,
    }
}

/// `cd DIR && COMMAND` as the request COMMAND alone makes from DIR.
///
/// The shell model must prove the pair: two exact segments joined by `&&`, a
/// plain `cd` with one operand the shell cannot redirect, and no redirect,
/// substitution, wrapper or environment prefix on either side. Uncertain
/// parsing, a semicolon and extra commands keep their normal review.
fn after_cd(request: &LocalCliHookRequestV1) -> Option<LocalCliHookRequestV1> {
    let (command, cwd) = cd_then_launch(
        &request.command,
        &request.cwd,
        request.home_dir.as_deref(),
        &request.env,
    )?;
    let mut alone = request.clone();
    alone.command = command;
    alone.cwd = cwd;
    Some(alone)
}

/// `cd DIR && COMMAND` read as `COMMAND` launched from `DIR`: the command
/// text and the canonical directory, or `None` for any other shape. Only two
/// plain segments joined by `&&` qualify, with no redirect, substitution,
/// wrapper or environment prefix, so the launch is exactly what the shell
/// runs. A `cd` operand the shell could resolve elsewhere (an option, a `..`
/// part, a searched name without the caller's environment or with `CDPATH`)
/// names no directory.
pub(crate) fn cd_then_launch(
    text: &str,
    cwd: &str,
    home_dir: Option<&str>,
    env: &std::collections::BTreeMap<String, String>,
) -> Option<(String, String)> {
    if text.trim().is_empty() {
        return None;
    }
    let model = parse_shell_command(
        text,
        Some(std::path::Path::new(cwd)),
        home_dir.map(std::path::Path::new),
        "posix",
        "shell_string",
        "guard-shell",
        true,
    );
    if model.confidence != "exact"
        || model.segments.len() != 2
        || !model.redirects.is_empty()
        || !model.embedded_commands.is_empty()
        || !model.wrapper_chain.is_empty()
    {
        return None;
    }
    let first = &model.segments[0];
    let launched = &model.segments[1];
    if first.executable.as_deref() != Some("cd")
        || first.arguments.len() != 1
        || first.path_overridden
        || !first.wrapper_chain.is_empty()
        || !first.environment_names.is_empty()
        || launched.executable.is_none()
        || launched.path_overridden
        || !launched.wrapper_chain.is_empty()
        || !launched.environment_names.is_empty()
    {
        return None;
    }
    let separator: String = model
        .normalized_text
        .chars()
        .skip(first.end)
        .take(launched.start.checked_sub(first.end)?)
        .collect();
    if separator.trim() != "&&" {
        return None;
    }
    // Do not infer the directory when the shell could select a different one
    // than the one canonicalized here. Logical cd handles '..' before
    // symlinks; searched operands can be redirected by CDPATH.
    let operand = first.arguments[0].as_str();
    if operand.starts_with('-') || operand.split('/').any(|part| part == "..") {
        return None;
    }
    let searched = !operand.starts_with('/') && operand.split('/').next() != Some(".");
    // Without the caller's environment, CDPATH cannot be ruled out.
    if searched && (env.is_empty() || env.keys().any(|name| name.eq_ignore_ascii_case("CDPATH"))) {
        return None;
    }
    let directory = std::fs::canonicalize(std::path::Path::new(cwd).join(operand)).ok()?;
    if !directory.is_dir() {
        return None;
    }
    // Without a wrapper chain the normalized text is the trimmed command, so
    // the second segment runs from its start to the end of the text.
    let command: String = model.normalized_text.chars().skip(launched.start).collect();
    let command = command.trim();
    if command.is_empty() {
        return None;
    }
    Some((command.to_owned(), directory.to_str()?.to_owned()))
}
