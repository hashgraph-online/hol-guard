//! A command list piped as one stream into text filters:
//! `{ rg -l a src/one.ts; rg -l a src/two.ts; } | head -100`, which is also
//! what a loop piped the same way unrolls to.
//!
//! The filters only reshape what they read and print it, so the stream they
//! read changes what is shown and nothing else. The group is therefore as safe
//! as its list run on its own, provided each filter is safe after any
//! producer. Both halves are decided by the ordinary proofs: the list as the
//! text inside the braces, and the filters behind a constant producer.
//!
//! Only a filter whose proof does not depend on what it reads qualifies.
//! `xargs`, an interpreter or a `while read` loop turn their input into
//! commands or file names, so the producer is part of what they run, and
//! splitting the stream from them would decide a different command. Those
//! keep the group's review.
//!
//! Only an allow is taken from this reading. The rewritten text is never what
//! runs: a sandbox or a saved decision has to stay bound to the submitted
//! command, so anything short of an allow keeps the group's own decision.

use super::{CommandModelRequestV1, PreToolDecisionV1};

const MAX_COMMAND_BYTES: usize = 8192;

/// Filters that read standard input and print a reshaping of it. Their
/// options are still screened by the proof the filters half goes through.
const FILTERS: &[&str] = &[
    "head", "tail", "wc", "sort", "uniq", "grep", "egrep", "fgrep", "rg", "cut", "tr", "cat", "nl",
    "tac", "rev", "fold", "column", "jq",
];

/// The list inside a leading brace group and the filter stages piped after
/// it, or `None` unless the command is exactly `{ LIST; } | FILTER...`.
pub(super) fn split(command: &str) -> Option<(String, String)> {
    let command = command.trim();
    if command.len() > MAX_COMMAND_BYTES || command.contains("<<") {
        return None;
    }
    let chars: Vec<char> = command.chars().collect();
    let (open, close) = super::brace_group::unquoted_braces(&chars)?;
    if open != 0 || !chars.get(1).is_some_and(|c| c.is_whitespace()) {
        return None;
    }
    let inner: String = chars[1..close].iter().collect();
    let body = inner.trim_end().strip_suffix(';')?.trim();
    let after: String = chars[close + 1..].iter().collect();
    let filters = after.trim_start().strip_prefix('|')?.trim();
    if body.is_empty() || filters.starts_with('|') || !filter_stages(filters) {
        return None;
    }
    Some((body.to_owned(), filters.to_owned()))
}

/// The stages after a loop's `done`, when they are a pipe into filters this
/// reading admits: the text after the `|`, or `None`.
pub(super) fn filter_tail(tail: &str) -> Option<String> {
    let filters = tail.trim().strip_prefix('|')?.trim();
    (!filters.starts_with('|') && filter_stages(filters)).then(|| filters.to_owned())
}

/// Whether the text is one or more `|`-separated stages, each starting with
/// a filter word, with nothing the shell would read as another command,
/// an expansion or a redirection.
fn filter_stages(text: &str) -> bool {
    let mut stages: Vec<String> = vec![String::new()];
    let mut single = false;
    let mut double = false;
    for c in text.chars() {
        if single {
            single = c != '\'';
        } else if double {
            if matches!(c, '$' | '`' | '\\') {
                return false;
            }
            double = c != '"';
        } else {
            match c {
                '\'' => single = true,
                '"' => double = true,
                '|' => {
                    stages.push(String::new());
                    continue;
                }
                ';' | '&' | '\n' | '<' | '>' | '$' | '`' | '\\' | '(' | ')' | '{' | '}' | '#'
                | '*' | '?' | '[' | '~' => return false,
                _ => {}
            }
        }
        if let Some(stage) = stages.last_mut() {
            stage.push(c);
        }
    }
    !single
        && !double
        && stages.iter().all(|stage| {
            stage
                .split_whitespace()
                .next()
                .is_some_and(|word| FILTERS.contains(&word))
        })
}

/// The group's decision read as its list and its filters, when both halves
/// are allowed on their own.
pub(super) fn decision(
    request: &CommandModelRequestV1,
    home_dir: Option<&str>,
    cwd: Option<&str>,
    deadline: Option<std::time::Instant>,
    execution_environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
    guard_home: Option<&str>,
    round: usize,
) -> Option<PreToolDecisionV1> {
    if round + 1 >= super::MAX_REWRITE_ROUNDS {
        return None;
    }
    let (body, filters) = split(&request.command)?;
    let half = |command: String| CommandModelRequestV1 {
        command,
        ..request.clone()
    };
    let filtered = super::evaluate_single_command(
        &half(format!("printf x | {filters}")),
        home_dir,
        cwd,
        deadline,
        execution_environment,
        guard_home,
    )
    .ok()?;
    if filtered.minimum_action != "allow" {
        return None;
    }
    let mut listed = super::evaluate_rewritten(
        &half(body),
        home_dir,
        cwd,
        deadline,
        execution_environment,
        guard_home,
        round + 1,
    )
    .ok()?;
    if listed.minimum_action != "allow" {
        return None;
    }
    // Extension controls read the decision's model, so the filters ride
    // along behind the list: a rule written for `sort` must still see it.
    // The constant producer is the only segment dropped, and anything else
    // in its place keeps the group's review.
    let mut filter_segments = filtered.command_model.segments.into_iter();
    if filter_segments
        .next()
        .is_none_or(|producer| producer.executable.as_deref() != Some("printf"))
    {
        return None;
    }
    listed.command_model.segments.extend(filter_segments);
    Some(listed)
}

#[cfg(test)]
#[path = "piped_group_tests.rs"]
mod tests;
