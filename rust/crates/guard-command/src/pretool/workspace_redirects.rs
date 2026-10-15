//! Redirects inside the workspace sandbox.
//!
//! The ordinary redirect projection removes a write only from a single
//! segment and only to a bounded, non-hidden target, because outside a
//! sandbox an earlier segment could retarget the write through `cd` or a
//! symlink. Inside `workspace-contained-v1` the kernel confines every write
//! and read, so compound commands whose redirects name literal paths may run
//! there too. This projection removes those redirects so the command that
//! remains can be classified exactly. It never decides by itself: the
//! projected command must still earn the workspace profile, and the raw text
//! is what runs.

use std::path::Path;
use std::time::Instant;

use guard_contracts::{GuardExecutionEnvironmentV1, PreToolResultV1};
use serde_json::Value;

use super::redirect_projection::{
    boundary, remove_quoted_heredoc, skip_heredoc_bodies, trailing_word,
};
use crate::native_command_controls::CompiledNativeCommandControls;
use crate::pretool::workspace_contained::Shape;
use crate::CommandModelRequestV1;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Quote {
    None,
    Single,
    Double,
}

/// The command with every literal-path redirect, descriptor copy and quoted
/// `cat` heredoc removed. `None` when nothing was removed or any redirect has
/// another form: process substitution, a computed or home-relative target, a
/// descriptor above 2, a herestring, or a heredoc fed to anything but `cat`.
pub(crate) fn project(raw: &str) -> Option<String> {
    project_scan(raw).map(|(projected, _, _)| projected)
}

/// [`project`], and whether any removed redirect names a file other than
/// `/dev/null`, which no link in the workspace can retarget.
pub(crate) fn project_naming_files(raw: &str) -> Option<(String, bool)> {
    project_scan(raw).map(|(projected, _, names_files)| (projected, names_files))
}

/// [`project`] with, for each byte of the projection, the index of the raw
/// character it came from. Bytes the projection inserts take the index of the
/// redirect they replace.
fn project_mapped(raw: &str) -> Option<(String, Vec<usize>)> {
    project_scan(raw).map(|(projected, map, _)| (projected, map))
}

fn project_scan(raw: &str) -> Option<(String, Vec<usize>, bool)> {
    let chars: Vec<char> = raw.chars().collect();
    let mut out = String::with_capacity(raw.len());
    let mut map: Vec<usize> = Vec::with_capacity(raw.len());
    let mut heredocs: Vec<(String, bool)> = Vec::new();
    let (mut quote, mut escaped, mut removed) = (Quote::None, false, false);
    let mut names_files = false;
    let mut index = 0usize;
    let mut origin = 0usize;
    while index < chars.len() {
        // Bytes kept from earlier iterations are never rewritten, so only
        // the ones the last iteration appended need an origin.
        map.truncate(out.len());
        map.resize(out.len(), origin);
        origin = index;
        let current = chars[index];
        if escaped {
            escaped = false;
            out.push(current);
            index += 1;
            continue;
        }
        match quote {
            Quote::Single => {
                quote = if current == '\'' { Quote::None } else { quote };
                out.push(current);
                index += 1;
                continue;
            }
            Quote::Double => {
                if current == '"' {
                    quote = Quote::None;
                } else if current == '\\' {
                    escaped = true;
                }
                out.push(current);
                index += 1;
                continue;
            }
            Quote::None => {}
        }
        match current {
            '\'' => quote = Quote::Single,
            '"' => quote = Quote::Double,
            '\\' => escaped = true,
            '\n' if !heredocs.is_empty() => {
                out.push('\n');
                index = skip_heredoc_bodies(&chars, index + 1, &mut heredocs)?;
                continue;
            }
            '<' if chars.get(index + 1) == Some(&'<') => {
                // A heredoc is stdin. Only `cat` is known to treat it as data.
                if current_segment(&out).trim() != "cat" {
                    return None;
                }
                index = remove_quoted_heredoc(&chars, index, &mut out, &mut heredocs)?;
                index = rejoin(&chars, index, &mut out);
                removed = true;
                continue;
            }
            '<' | '>' => {
                index = remove_redirect(&chars, index, &mut out, &mut names_files)?;
                index = rejoin(&chars, index, &mut out);
                removed = true;
                continue;
            }
            _ => {}
        }
        out.push(current);
        index += 1;
    }
    map.truncate(out.len());
    map.resize(out.len(), origin);
    if !removed || quote != Quote::None || escaped || !heredocs.is_empty() {
        return None;
    }
    let lead = out.len() - out.trim_start().len();
    let projected = out.trim();
    let map = map[lead..lead + projected.len()].to_vec();
    Some((projected.to_owned(), map, names_files))
}

/// The shape the projected command earns, with a bootstrapped `git init`
/// sliced from the raw bytes that will run. `None` when the init segment
/// itself carried a redirect, so the raw text cannot be split the same way.
pub(crate) fn contained_shape(raw: &str, projected: &str, workspace: &Path) -> Option<Shape> {
    let (mapped, map) = project_mapped(raw)?;
    if mapped != projected {
        return None;
    }
    let model = crate::parse_command(&CommandModelRequestV1 {
        command: projected.to_owned(),
        dialect: "posix".into(),
        transport: "shell_string".into(),
        extraction_provenance: "pre-tool-generic".into(),
    })
    .ok()?;
    let mut shape = crate::pretool::command_shape(&model, workspace, Some(projected))?;
    let Some((start, end)) = shape.init_span else {
        return Some(shape);
    };
    let origin = |position: usize| {
        let byte = projected.char_indices().nth(position)?.0;
        map.get(byte).copied()
    };
    let (raw_start, raw_end) = (origin(start)?, origin(end.checked_sub(1)?)? + 1);
    let raw_chars: Vec<char> = raw.chars().collect();
    let init: String = raw_chars.get(raw_start..raw_end)?.iter().collect();
    let expected: String = projected.chars().skip(start).take(end - start).collect();
    if init != expected {
        return None;
    }
    let (prefix, rest) =
        crate::pretool::workspace_contained::split_at_init(raw, raw_start, raw_end)?;
    if shape.prefix.is_some() != prefix.is_some()
        || shape.remainder.as_ref().is_some_and(String::is_empty) != rest.is_empty()
    {
        return None;
    }
    shape.prefix = prefix;
    shape.remainder = Some(rest);
    Some(shape)
}

/// Leaves one space where a redirect was, so the projection keeps the
/// spacing the parser normalizes to.
fn rejoin(chars: &[char], mut index: usize, out: &mut String) -> usize {
    // An escaped space is part of a word; dropping it could join lines.
    while out.ends_with([' ', '\t']) && !out[..out.len() - 1].ends_with('\\') {
        out.pop();
    }
    while matches!(chars.get(index), Some(' ' | '\t')) {
        index += 1;
    }
    if !out.is_empty() && chars.get(index).is_some_and(|value| *value != '\n') {
        out.push(' ');
    }
    index
}

/// A compound command whose redirects all name literal paths runs in the
/// workspace sandbox when the command without them earns that profile and
/// the raw text targets nothing sensitive. The sandbox confines the files the
/// redirects open, which the single-segment projection cannot prove.
#[allow(clippy::too_many_arguments)]
pub(super) fn contained(
    harness: &str,
    event: &str,
    payload: &Value,
    command: &str,
    controls: Option<&CompiledNativeCommandControls>,
    deadline: Option<Instant>,
    context: crate::pretool::PathContext<'_>,
    execution_environment: Option<&GuardExecutionEnvironmentV1>,
) -> Option<PreToolResultV1> {
    if !crate::pretool::workspace_contained::host_eligible(harness, event) {
        return None;
    }
    // A command the bounded-write projection takes runs directly instead: a
    // single command, or a chain whose only write is its first step's,
    // followed by plain readers. One it declines, such as a write to
    // `.tool-versions`, or a chain beside local Git writes, runs here.
    let stripped = project(command)?;
    let direct = super::redirect_projection::project(command, context);
    // A later read of a written file spelled from the root names what the
    // projection's relative spelling names, so both earn the same floor.
    let projected_text = match &direct {
        Some(projection) => projection.relative_reads(stripped.clone(), context.cwd),
        None => stripped.clone(),
    };
    let projected_payload =
        super::command_rewrite::payload_with_command(payload, command, &projected_text);
    let projected = super::evaluate_envelope(
        harness,
        event,
        &projected_payload,
        controls,
        deadline,
        context,
        execution_environment,
        false,
    );
    let workspace = crate::pretool::workspace_contained::admitted_workspace(context)?;
    // A redirect aimed outside the workspace is not workspace work: the
    // sandbox would only refuse the write, so it keeps its review.
    if crate::pretool::workspace_contained::redirect_leaves(command, &workspace) {
        return None;
    }
    // A projection that earns a plain allow runs in the sandbox too: the
    // redirects still need its confinement, and the command needs nothing
    // the sandbox withholds when it stays offline.
    let single = direct.is_none();
    let runs_directly = direct
        .is_some_and(|projection| projection.bounded_writes && projection.git_chain.is_none());
    let allowed = projected.minimum_action == "allow"
        && !projected.action.sensitive_target
        && !runs_directly
        && stays_offline(&projected_text, single);
    // macOS claims package and Node tool commands with narrower profiles
    // before the workspace route runs. The redirect disqualifies those, so the
    // workspace sandbox takes the command once it passes that route's gate.
    let home = context.home_dir.map(Path::new);
    let narrower = super::redirect_projection::package_profile(&projected.reason_code)
        && projected.minimum_action == "sandbox-required"
        && !projected.action.sensitive_target
        && crate::pretool::workspace_contained::runner::runners_admitted(
            &stripped, &workspace, home,
        )
        && crate::pretool::workspace_git_environment::session_git_variables(execution_environment)
            .and_then(|variables| {
                crate::pretool::workspace_git_config::workspace_write_denials(
                    &workspace, home, &variables,
                )
            })
            .is_some();
    if projected.reason_code != crate::pretool::workspace_contained::REASON && !allowed && !narrower
    {
        return None;
    }
    // The sandbox runs the command as written, so its shape is the stripped text's.
    contained_shape(command, &stripped, &workspace)?;
    let raw = super::evaluate_envelope(
        harness,
        event,
        payload,
        None,
        deadline,
        context,
        execution_environment,
        false,
    );
    // On macOS the raw text can earn the same narrower profile on its own.
    let raw_reviewed = raw.reason_code == "native_command_review_required"
        || (narrower && raw.reason_code == projected.reason_code);
    if raw.action.sensitive_target || !raw_reviewed {
        return None;
    }
    let mut projected = projected;
    if allowed || narrower {
        crate::pretool::workspace_contained::mark_contained(&mut projected);
    }
    Some(projected)
}

/// An allowed command still works in the sandbox when it reaches no
/// network, unlike GitHub and registry queries or Git remote operations.
/// A single command counts only when `single` says the bounded-write
/// projection will not run it directly.
fn stays_offline(projected: &str, single: bool) -> bool {
    let Ok(model) = crate::parse_command(&CommandModelRequestV1 {
        command: projected.to_owned(),
        dialect: "posix".into(),
        transport: "shell_string".into(),
        extraction_provenance: "pre-tool-generic".into(),
    }) else {
        return false;
    };
    (model.segments.len() > 1 || (single && model.segments.len() == 1))
        && !model.segments.iter().any(|segment| {
            let Some(executable) = segment.executable.as_deref() else {
                return true;
            };
            let any = |verbs: &[&str]| {
                segment
                    .arguments
                    .iter()
                    .any(|argument| verbs.contains(&argument.as_str()))
            };
            match crate::pretool::executable_basename(executable) {
                "gh" | "curl" | "kubectl" => true,
                "git" => any(&[
                    "fetch",
                    "pull",
                    "push",
                    "ls-remote",
                    "clone",
                    "remote",
                    "submodule",
                ]),
                "npm" | "pnpm" | "yarn" | "bun" => any(&[
                    "view", "info", "show", "v", "outdated", "search", "ping", "whoami", "audit",
                ]),
                _ => false,
            }
        })
}

/// The text of the simple command being written, after the last separator.
fn current_segment(out: &str) -> &str {
    let start = out
        .rfind([';', '|', '&', '\n', '(', ')', '{', '}'])
        .map_or(0, |position| position + 1);
    &out[start..]
}

fn remove_redirect(
    chars: &[char],
    start: usize,
    out: &mut String,
    names_files: &mut bool,
) -> Option<usize> {
    let input = chars[start] == '<';
    let mut index = start + 1;
    let descriptor = trailing_word(out).to_owned();
    match descriptor.as_str() {
        "" => {}
        "1" | "2" if !input => out.truncate(out.len() - 1),
        "0" if input => out.truncate(out.len() - 1),
        _ if descriptor.chars().all(|value| value.is_ascii_digit()) => return None,
        // `&>` means background-then-redirect under POSIX `sh`.
        _ if descriptor.ends_with('&') => return None,
        _ => {}
    }
    if chars.get(index) == Some(&'&') {
        // A descriptor copy between stdout and stderr moves no file data.
        if input
            || !matches!(chars.get(index + 1), Some('1' | '2'))
            || !boundary(chars.get(index + 2))
        {
            return None;
        }
        out.push(' ');
        return Some(index + 2);
    }
    if !input && matches!(chars.get(index), Some('>' | '|')) {
        index += 1;
    }
    if matches!(chars.get(index), Some('|' | '(' | '>' | '<' | '&')) {
        return None;
    }
    while matches!(chars.get(index), Some(' ' | '\t')) {
        index += 1;
    }
    let target_start = index;
    while chars.get(index).is_some_and(|value| {
        !value.is_whitespace() && !matches!(value, ';' | '|' | '&' | ')' | '(' | '<' | '>')
    }) {
        index += 1;
    }
    let target: String = chars[target_start..index].iter().collect();
    if !literal_target(&target) {
        return None;
    }
    *names_files |= target != "/dev/null";
    out.push(' ');
    Some(index)
}

/// A path the shell opens exactly as written: no expansion, glob, quote or
/// home prefix. The sandbox decides whether it may be written.
fn literal_target(target: &str) -> bool {
    !target.is_empty()
        && target.len() <= 4096
        && !target.starts_with(['-', '~'])
        && target
            .chars()
            .all(|value| value.is_ascii_alphanumeric() || "._-/+@%,=:".contains(value))
}

#[cfg(test)]
#[path = "workspace_redirects_tests.rs"]
mod tests;
