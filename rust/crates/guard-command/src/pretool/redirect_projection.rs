//! Plain file redirects stop the shell parser from modelling a command at
//! all. This projection removes only literal-path output redirects and quoted
//! heredoc bodies fed to `cat`, so the command that actually executes keeps
//! every intrinsic and extension floor of its own. Any other redirect form,
//! and any projection that does not parse exactly, keeps the fail-closed path.

use crate::CommandModelRequestV1;
use guard_contracts::PreToolResultV1;

#[derive(Debug, PartialEq, Eq)]
pub(super) struct RedirectProjection {
    pub(super) command: String,
    pub(super) writes_file: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Quote {
    None,
    Single,
    Double,
}

const MAX_HEREDOC_DELIMITER: usize = 64;

pub(super) fn project(
    raw: &str,
    context: super::super::PathContext<'_>,
) -> Option<RedirectProjection> {
    let chars: Vec<char> = raw.chars().collect();
    let mut out = String::with_capacity(raw.len());
    let mut quote = Quote::None;
    let mut escaped = false;
    let mut heredocs: Vec<(String, bool)> = Vec::new();
    let mut saw_heredoc = false;
    let mut removed = false;
    let mut writes_file = false;
    let mut index = 0usize;
    while index < chars.len() {
        let current = chars[index];
        if escaped {
            escaped = false;
            out.push(current);
            index += 1;
            continue;
        }
        match quote {
            Quote::Single => {
                if current == '\'' {
                    quote = Quote::None;
                }
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
            '>' => {
                index = remove_output_redirect(&chars, index, &mut out, context, &mut writes_file)?;
                removed = true;
                continue;
            }
            '<' => {
                index = remove_quoted_heredoc(&chars, index, &mut out, &mut heredocs)?;
                saw_heredoc = true;
                removed = true;
                continue;
            }
            _ => {}
        }
        out.push(current);
        index += 1;
    }
    if !removed || quote != Quote::None || escaped || !heredocs.is_empty() {
        return None;
    }
    let command = out.trim().to_owned();
    let model = crate::parse_command(&CommandModelRequestV1 {
        command: command.clone(),
        dialect: "posix".to_owned(),
        transport: "shell_string".to_owned(),
        extraction_provenance: "pre-tool-generic".to_owned(),
    })
    .ok()?;
    // An earlier segment could change directory or create a symlink before
    // the shell opens the target, so file writes need a single segment.
    if model.confidence != "exact"
        || model.uncertainty_reason.is_some()
        || model.segments.is_empty()
        || (writes_file && model.segments.len() != 1)
    {
        return None;
    }
    // A heredoc body is stdin. Only `cat` is known to treat it as data.
    if saw_heredoc
        && !(model.segments.len() == 1
            && model.segments[0].wrapper_chain.is_empty()
            && model.segments[0].environment_names.is_empty()
            && model.segments[0].executable.as_deref() == Some("cat")
            && model.segments[0].arguments.is_empty())
    {
        return None;
    }
    Some(RedirectProjection {
        command,
        writes_file,
    })
}

/// Keep the projected command's floors and raise them by any independent
/// floor of the raw command. The raw text's generic "unparsed command"
/// review is the only floor the projection discharges, except that a file
/// write still requires review.
fn redirect_disqualifies_containment(reason: &str) -> bool {
    // A file redirect is a shell effect. Pytest and inline-eval profiles are
    // only valid for the exact command, so the projection must not inherit them.
    matches!(
        reason,
        "native_pytest_readonly_containment_required"
            | "native_python_eval_readonly_containment_required"
            | "native_node_eval_readonly_containment_required"
    )
}

pub(super) fn join(
    mut projected: PreToolResultV1,
    raw: PreToolResultV1,
    writes_file: bool,
) -> PreToolResultV1 {
    // Stripping a benign descriptor copy must not replace an allow the raw
    // command already earned. A file write still goes through the floors below.
    if !writes_file
        && raw.decision == "allow"
        && matches!(raw.minimum_action.as_str(), "allow" | "warn")
    {
        return raw;
    }
    if writes_file && redirect_disqualifies_containment(&projected.reason_code) {
        projected.minimum_action = "review".into();
        projected.policy_action = "review".into();
        projected.decision = "deny".into();
        projected.explicitly_benign = false;
        projected.reason_code = "native_command_redirect_write_review".into();
        projected.reason =
            "HOL Guard requires review because this command writes its output to a file.".into();
    }
    projected.action.sensitive_target |= raw.action.sensitive_target;
    projected.action.bounded &= raw.action.bounded;
    if raw.reason_code != "native_command_review_required"
        && raw.reason_code != "native_command_extension_evaluation_failed"
        && rank(&raw.minimum_action) > rank(&projected.minimum_action)
    {
        projected.minimum_action = raw.minimum_action;
        projected.policy_action = raw.policy_action;
        projected.decision = raw.decision;
        projected.reason_code = raw.reason_code;
        projected.reason = raw.reason;
    }
    if writes_file && rank(&projected.minimum_action) < rank("review") {
        projected.minimum_action = "review".into();
        projected.policy_action = "review".into();
        projected.decision = "deny".into();
        projected.reason_code = "native_command_redirect_write_review".into();
        projected.reason =
            "HOL Guard requires review because this command writes its output to a file.".into();
    }
    projected.explicitly_benign &=
        projected.minimum_action == "allow" && !projected.action.sensitive_target;
    projected
}

fn rank(action: &str) -> u8 {
    match action {
        "allow" => 0,
        "warn" => 1,
        "review" => 2,
        "require-reapproval" => 3,
        "sandbox-required" => 4,
        _ => 5,
    }
}

fn remove_output_redirect(
    chars: &[char],
    start: usize,
    out: &mut String,
    context: super::super::PathContext<'_>,
    writes_file: &mut bool,
) -> Option<usize> {
    let mut index = start + 1;
    let descriptor = trailing_word(out).to_owned();
    let duplicate = chars.get(index) == Some(&'&');
    match descriptor.as_str() {
        "" => {}
        "1" | "2" | "&" => {
            out.truncate(out.len() - 1);
        }
        _ if descriptor.chars().all(|value| value.is_ascii_digit()) => return None,
        _ => {}
    }
    if duplicate {
        // Only stderr-to-stdout is a bounded descriptor copy.
        if descriptor != "2"
            || chars.get(index + 1) != Some(&'1')
            || !boundary(chars.get(index + 2))
        {
            return None;
        }
        out.push_str(" 2>&1");
        return Some(index + 2);
    }
    if chars.get(index) == Some(&'>') {
        index += 1;
    }
    if matches!(chars.get(index), Some('|' | '(' | '>' | '<' | '&')) {
        return None;
    }
    while matches!(chars.get(index), Some(' ' | '\t')) {
        index += 1;
    }
    let target_start = index;
    while chars
        .get(index)
        .is_some_and(|value| !value.is_whitespace() && !matches!(value, ';' | '|' | '&' | ')'))
    {
        index += 1;
    }
    let target: String = chars[target_start..index].iter().collect();
    if target == "/dev/null" {
        // Stderr-to-null is part of the read-only proof. Dropping it makes a
        // benign pipeline look like an unproven command.
        if descriptor == "2" {
            out.push_str("2>/dev/null");
        }
        out.push(' ');
        return Some(index);
    }
    if !safe_output_target(&target, context) {
        return None;
    }
    *writes_file = true;
    out.push(' ');
    Some(index)
}

fn remove_quoted_heredoc(
    chars: &[char],
    start: usize,
    out: &mut String,
    heredocs: &mut Vec<(String, bool)>,
) -> Option<usize> {
    if chars.get(start + 1) != Some(&'<') || chars.get(start + 2) == Some(&'<') {
        return None;
    }
    if !trailing_word(out).is_empty() {
        return None;
    }
    let mut index = start + 2;
    let strip_tabs = chars.get(index) == Some(&'-');
    if strip_tabs {
        index += 1;
    }
    while matches!(chars.get(index), Some(' ' | '\t')) {
        index += 1;
    }
    // An unquoted delimiter expands `$(...)` inside the body.
    let delimiter_quote = *chars
        .get(index)
        .filter(|value| matches!(value, '\'' | '"'))?;
    index += 1;
    let delimiter_start = index;
    while chars
        .get(index)
        .is_some_and(|value| value.is_ascii_alphanumeric() || *value == '_')
    {
        index += 1;
    }
    let delimiter: String = chars[delimiter_start..index].iter().collect();
    if delimiter.is_empty()
        || delimiter.len() > MAX_HEREDOC_DELIMITER
        || chars.get(index) != Some(&delimiter_quote)
        || !boundary(chars.get(index + 1))
    {
        return None;
    }
    heredocs.push((delimiter, strip_tabs));
    out.push(' ');
    Some(index + 1)
}

fn skip_heredoc_bodies(
    chars: &[char],
    mut index: usize,
    heredocs: &mut Vec<(String, bool)>,
) -> Option<usize> {
    for (delimiter, strip_tabs) in heredocs.drain(..) {
        loop {
            if index >= chars.len() {
                return None;
            }
            let end = chars[index..]
                .iter()
                .position(|value| *value == '\n')
                .map_or(chars.len(), |offset| index + offset);
            let line: String = chars[index..end].iter().collect();
            let line = if strip_tabs {
                line.trim_start_matches('\t')
            } else {
                line.as_str()
            };
            let matched = line == delimiter;
            index = end + 1;
            if matched {
                break;
            }
        }
    }
    Some(index.min(chars.len()))
}

fn trailing_word(out: &str) -> &str {
    let start = out
        .rfind(|value: char| value.is_whitespace() || matches!(value, ';' | '|'))
        .map_or(0, |position| position + 1);
    &out[start..]
}

fn boundary(value: Option<&char>) -> bool {
    value.is_none_or(|value| value.is_whitespace() || matches!(value, ';' | '|' | '&'))
}

fn posix_temp_file(target: &str) -> bool {
    let Some(rest) = target
        .strip_prefix("/tmp/")
        .or_else(|| target.strip_prefix("/private/tmp/"))
    else {
        return false;
    };
    !rest.is_empty()
        && !rest.contains('/')
        && !rest.contains("..")
        && rest
            .chars()
            .all(|value| value.is_ascii_alphanumeric() || "._-+@%,=".contains(value))
}

fn safe_output_target(target: &str, context: super::super::PathContext<'_>) -> bool {
    if target.is_empty()
        || target.len() > 4096
        || target.starts_with(['-', '~'])
        || !target
            .chars()
            .all(|value| value.is_ascii_alphanumeric() || "._-/+@%,=:".contains(value))
        || super::super::sensitive_command(target)
    {
        return false;
    }
    let path = std::path::Path::new(target);
    // Windows does not treat `/tmp/file` as absolute, so the host path walk
    // never sees the POSIX temp directory. A single literal temp segment is
    // still a bounded file write and keeps the review floor.
    if !path.is_absolute() && posix_temp_file(target) {
        return true;
    }
    // A POSIX-rooted path other than the bounded temp-file exception cannot
    // be resolved safely with Windows host path semantics.
    #[cfg(windows)]
    if target.starts_with('/') {
        return false;
    }
    // Hidden components cover dotfiles, `.git/hooks`, and `.env` targets.
    if path.components().any(|component| match component {
        std::path::Component::Normal(name) => {
            name.to_str().is_none_or(|name| name.starts_with('.'))
        }
        std::path::Component::RootDir | std::path::Component::CurDir => false,
        _ => true,
    }) {
        return false;
    }
    let cwd = context
        .cwd
        .map(std::path::Path::new)
        .filter(|cwd| cwd.is_absolute());
    if path.is_absolute() {
        if let Some(base) = ["/tmp", "/private/tmp"]
            .into_iter()
            .map(std::path::Path::new)
            .find(|base| path.starts_with(base) && path != *base)
        {
            return path
                .strip_prefix(base)
                .is_ok_and(|rest| no_symlink_components(base, rest));
        }
        return cwd.is_some_and(|cwd| {
            path != cwd
                && path
                    .strip_prefix(cwd)
                    .is_ok_and(|rest| no_symlink_components(cwd, rest))
        });
    }
    cwd.is_some_and(|cwd| no_symlink_components(cwd, path))
}

/// Writing through an existing symlink could reach any file the user owns.
fn no_symlink_components(base: &std::path::Path, relative: &std::path::Path) -> bool {
    let mut current = base.to_path_buf();
    for component in relative.components() {
        current.push(component);
        match std::fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => return false,
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return true,
            Err(_) => return false,
        }
    }
    true
}

#[cfg(test)]
#[path = "redirect_projection_tests.rs"]
mod tests;
