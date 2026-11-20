//! Narrow changed-script connector lookup for compound shell commands.
use super::*;

pub(super) fn changed_connector(request: &LocalCliHookRequestV1) -> Option<Value> {
    let records = unlisted(request, true).ok()?;
    let records = if records.is_empty() {
        relative_script_after_cd(request)?
    } else {
        records
    };
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

/// Only recognize a literal `cd DIR && ./script` with two exact segments.
/// This supplies a card for an already-reviewing command, never an Allow
/// verdict. Uncertain parsing, redirects, substitutions and extra commands
/// retain their normal review card.
fn relative_script_after_cd(request: &LocalCliHookRequestV1) -> Option<Vec<UnlistedCliV1>> {
    if request.command.trim().is_empty() {
        return None;
    }
    let model = parse_shell_command(
        &request.command,
        Some(std::path::Path::new(&request.cwd)),
        request.home_dir.as_deref().map(std::path::Path::new),
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
    let script = &model.segments[1];
    if first.executable.as_deref() != Some("cd")
        || first.arguments.len() != 1
        || first.path_overridden
        || !first.wrapper_chain.is_empty()
        || !first.environment_names.is_empty()
        || script.path_overridden
        || !script.wrapper_chain.is_empty()
        || !script.environment_names.is_empty()
    {
        return None;
    }
    let separator: String = model
        .normalized_text
        .chars()
        .skip(first.end)
        .take(script.start.checked_sub(first.end)?)
        .collect();
    if separator.trim() != "&&" {
        return None;
    }
    let executable = script.executable.as_deref()?;
    if !executable.starts_with("./")
        || !executable
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '.' | '_' | '-'))
    {
        return None;
    }
    let directory = std::fs::canonicalize(
        std::path::Path::new(&request.cwd).join(&first.arguments[0]),
    )
    .ok()?;
    if !directory.is_dir() {
        return None;
    }
    let cwd = directory.to_str()?;
    let records = identify(&Request {
        command_text: executable,
        cwd,
        home_dir: request.home_dir.as_deref(),
        user_home: &request.user_home,
        compound: false,
        env: &request.env,
        budget_ms: IDENTIFY_BUDGET_MS,
    })
    .ok()?;
    if records.len() != 1 || !records.iter().all(valid_unlisted) {
        return None;
    }
    Some(records)
}
