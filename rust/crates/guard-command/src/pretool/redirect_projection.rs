//! Plain file redirects stop the shell parser from modelling a command at
//! all. This projection removes only literal-path output redirects and quoted
//! heredoc bodies fed to `cat`, so the command that actually executes keeps
//! every intrinsic and extension floor of its own. Any other redirect form,
//! and any projection that does not parse exactly, keeps the fail-closed path.

use crate::CommandModelRequestV1;
use guard_contracts::PreToolResultV1;
use targets::{
    bounded_write, plan_note_output_target, relative_saved_reads, safe_output_target,
    sibling_heredoc_target,
};

#[path = "redirect_git_chain.rs"]
pub(super) mod git_chain;
#[path = "redirect_leading_chain.rs"]
mod leading_chain;
#[path = "redirect_targets.rs"]
mod targets;

#[derive(Debug, PartialEq, Eq)]
pub(super) struct RedirectProjection {
    pub(super) command: String,
    pub(super) writes_file: bool,
    /// Every file the redirects write passes the check a file-edit tool's
    /// write gets.
    pub(super) bounded_writes: bool,
    /// The files written beside local Git writes when [`git_chain::admits`]
    /// takes a chain; `None` for every other projection.
    pub(super) git_chain: Option<Vec<String>>,
    /// Every file written is a scratch file, where a network read's body
    /// may be saved.
    pub(super) scratch_writes: bool,
    /// [`crate::pretool::git_init_chain::admits`] took the chain, so only
    /// that proof may allow it: the targets were checked in the working
    /// directory, and a write after the `cd` lands in the new repository.
    init_chain: bool,
    /// The literal targets the removed redirects write.
    written: Vec<String>,
}

impl RedirectProjection {
    /// `text` with each later read of a written file below the working
    /// directory spelled relative, as [`project`] spells it.
    pub(super) fn relative_reads(&self, text: String, cwd: Option<&str>) -> String {
        relative_saved_reads(text, &self.written, cwd)
    }
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
    let mut targets: Vec<String> = Vec::new();
    let mut bounded_writes = true;
    let mut temporary_writes = true;
    let mut scratch_writes = true;
    // Whether a separator, group or substitution came before a file write,
    // so another step could run before the shell opens the file.
    let mut separated = false;
    let mut late_write = false;
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
                separated |= substitution(&chars, index);
                out.push(current);
                index += 1;
                continue;
            }
            Quote::None => {}
        }
        // `&>` is a redirect, not a separator.
        separated |= matches!(current, ';' | '|' | '\n' | '(' | ')' | '{' | '}')
            || (current == '&' && chars.get(index + 1) != Some(&'>'))
            || substitution(&chars, index);
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
                let written = targets.len();
                index = remove_output_redirect(
                    &chars,
                    index,
                    &mut out,
                    context,
                    &mut targets,
                    &mut bounded_writes,
                    &mut temporary_writes,
                )?;
                late_write |= separated && targets.len() > written;
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
    let writes_file = !targets.is_empty();
    let command = out.trim().to_owned();
    // Only kept descriptor copies (`2>&1`, `2>/dev/null`) were seen. The
    // parser models those, and the command as written already gets the full
    // evaluation with every control, so a join with an uncontrolled raw
    // evaluation could only lose a proven allow or a configured denial.
    // A copy glued to a separator (`;2>&1`) is the same command as the
    // spaced form. Reparsing the spaced form would name the redirect as the
    // program and review an interpreter the raw text still fails closed on.
    if same_command_aside_from_descriptor_spacing(raw, &command) {
        return None;
    }
    let command = relative_saved_reads(command, &targets, context.cwd);
    let model = crate::parse_command(&CommandModelRequestV1 {
        command: command.clone(),
        dialect: "posix".to_owned(),
        transport: "shell_string".to_owned(),
        extraction_provenance: "pre-tool-generic".to_owned(),
    })
    .ok()?;
    // An earlier segment could cd or create a symlink before the shell opens
    // a target, so a chain may only write absolute temp files beside peers.
    let temporary_chain =
        temporary_writes && super::super::chain_temporary::temporary_peers(&model);
    let chain = writes_file && model.segments.len() != 1 && !temporary_chain;
    let leading_write = chain && bounded_writes && !late_write && leading_chain::admits(&model);
    // Plain peers cannot change directory, rename a file or create a link,
    // so a write that follows one still opens the file the target check
    // proved: `cp /tmp/a.ts /tmp/b.ts && cat /tmp/a.ts > src/c.ts`.
    let peer_write = chain && bounded_writes && super::super::chain_temporary::peers_only(&model);
    scratch_writes &= targets.iter().all(|target| {
        crate::pretool::curl_reads::output_targets::scratch_output_target(target, context)
    });
    let git_chain =
        (chain && bounded_writes && git_chain::admits(&model, &targets)).then(|| targets.clone());
    let init_chain =
        chain && bounded_writes && crate::pretool::git_init_chain::admits(&model, &targets);
    if model.confidence != "exact"
        || model.uncertainty_reason.is_some()
        || model.segments.is_empty()
        || (chain && git_chain.is_none() && !leading_write && !init_chain && !peer_write)
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
    // A quoted heredoc is literal data, but the bare `cat` that remains reads
    // standard input, which only the workspace sandbox bounds. A plan note in
    // the harness home and a repository beside the session's directory lie
    // outside that sandbox, so the write checked above is all that is left to
    // prove, and a no-op stands in for the command.
    let command = if saw_heredoc
        && bounded_writes
        && writes_file
        && targets.iter().all(|target| {
            plan_note_output_target(target, context) || sibling_heredoc_target(target, context)
        }) {
        "true".to_owned()
    } else {
        command
    };
    Some(RedirectProjection {
        command,
        writes_file,
        bounded_writes,
        git_chain,
        scratch_writes,
        init_chain,
        written: targets,
    })
}

/// `$(` or a backquote: a command substitution runs before the redirect
/// that follows it opens its file.
fn substitution(chars: &[char], index: usize) -> bool {
    chars[index] == '`' || (chars[index] == '$' && chars.get(index + 1) == Some(&'('))
}

/// Keep the projected command's floors and raise them by any independent
/// floor of the raw command. The raw text's generic "unparsed command"
/// review is the only floor the projection discharges, except that a file
/// write still requires review unless its target passes the same check as a
/// file-edit tool's write and the command itself is allowed.
fn redirect_disqualifies_containment(reason: &str) -> bool {
    // A file redirect is a shell effect. Pytest and inline-eval profiles and
    // the proofs of Git's own writes are only valid for the exact command, so
    // the projection must not inherit them.
    // A network read's body is remote content, never a reviewed workspace edit.
    // The macOS read-only profiles split the raw text into the program's
    // arguments, so a redirect would reach the program instead of the shell.
    package_profile(reason)
        || matches!(
            reason,
            "native_git_readonly_containment_required"
                | "native_pytest_readonly_containment_required"
                | "native_python_eval_readonly_containment_required"
                | "native_node_eval_readonly_containment_required"
                | "native_bun_eval_readonly_containment_required"
                | "native_workspace_containment_required"
                | crate::pretool::git_config_reads::writes::REASON
                | crate::pretool::git_init_target::REASON
                | crate::pretool::curl_reads::NETWORK_READ_REASON
        )
}

/// The macOS package and Node tool profiles. A redirect disqualifies them; the
/// workspace sandbox may still take the command once its runner gate passes.
pub(super) fn package_profile(reason: &str) -> bool {
    matches!(
        reason,
        "native_package_test_readonly_containment_required"
            | "native_vitest_readonly_containment_required"
            | "native_node_tool_readonly_containment_required"
            | "native_node_test_readonly_containment_required"
            | "native_node_build_output_containment_required"
    )
}

pub(super) fn join(
    mut projected: PreToolResultV1,
    raw: PreToolResultV1,
    projection: &RedirectProjection,
) -> PreToolResultV1 {
    let (writes_file, bounded_writes) = (projection.writes_file, projection.bounded_writes);
    // Stripping a benign descriptor copy must not replace an allow the raw
    // command already earned. A file write still goes through the floors below.
    if !writes_file
        && raw.decision == "allow"
        && matches!(raw.minimum_action.as_str(), "allow" | "warn")
    {
        return raw;
    }
    // A network read's body may still be saved to a scratch file, which no
    // tool loads on its own.
    let scratch_body = projection.scratch_writes
        && projected.reason_code == crate::pretool::curl_reads::NETWORK_READ_REASON;
    let other_proof =
        projection.init_chain && projected.reason_code != crate::pretool::git_init_chain::REASON;
    if writes_file
        && !scratch_body
        && (other_proof || redirect_disqualifies_containment(&projected.reason_code))
    {
        write_review(&mut projected);
        projected.explicitly_benign = false;
    }
    projected.action.sensitive_target |= raw.action.sensitive_target;
    projected.action.bounded &= raw.action.bounded;
    // The raw text's sandbox route is the fallback for a write the parser
    // could not bound. Once the projection has bounded every target, it
    // discharges that route the same way it discharges the generic review.
    let contained_fallback =
        bounded_writes && raw.reason_code == "native_workspace_containment_required";
    if raw.reason_code != "native_command_review_required"
        && raw.reason_code != "native_command_extension_evaluation_failed"
        && !contained_fallback
        && rank(&raw.minimum_action) > rank(&projected.minimum_action)
    {
        projected.minimum_action = raw.minimum_action;
        projected.policy_action = raw.policy_action;
        projected.decision = raw.decision;
        projected.reason_code = raw.reason_code;
        projected.reason = raw.reason;
        // The raw text can earn a read-only profile on its own, which the
        // redirect disqualifies too; its workspace sandbox route stays.
        let profile = &projected.reason_code;
        if writes_file
            && (package_profile(profile) || profile.ends_with("_readonly_containment_required"))
        {
            write_review(&mut projected);
        }
    }
    // `echo done > notes.txt` is the same edit an agent's own write tool makes.
    let bounded = bounded_writes
        && projected.minimum_action == "allow"
        && projected.decision == "allow"
        && !projected.action.sensitive_target;
    if writes_file && !bounded && rank(&projected.minimum_action) < rank("review") {
        write_review(&mut projected);
    }
    projected.explicitly_benign &=
        projected.minimum_action == "allow" && !projected.action.sensitive_target;
    projected
}

fn write_review(result: &mut PreToolResultV1) {
    result.minimum_action = "review".into();
    result.policy_action = "review".into();
    result.decision = "deny".into();
    result.reason_code = "native_command_redirect_write_review".into();
    result.reason =
        "HOL Guard requires review because this command writes its output to a file.".into();
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

/// `2>&1` and `2>/dev/null` glued to `;`, `|`, or `&` name the same command
/// as the form with a space. Other redirects stay in the comparison, so
/// removing `> out` beside a kept copy still counts as a change.
fn same_command_aside_from_descriptor_spacing(raw: &str, command: &str) -> bool {
    spaced_descriptor_copies(raw)
        .split_whitespace()
        .eq(spaced_descriptor_copies(command).split_whitespace())
}

fn spaced_descriptor_copies(text: &str) -> String {
    const COPIES: &[&str] = &["2>&1", "2>/dev/null"];
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len() + 4);
    let mut index = 0usize;
    while index < chars.len() {
        if matches!(chars[index], ';' | '|' | '&') {
            if let Some(copy) = COPIES.iter().copied().find(|copy| {
                chars[index + 1..]
                    .iter()
                    .copied()
                    .take(copy.chars().count())
                    .eq(copy.chars())
            }) {
                out.push(chars[index]);
                out.push(' ');
                out.push_str(copy);
                index += 1 + copy.chars().count();
                continue;
            }
        }
        out.push(chars[index]);
        index += 1;
    }
    out
}

fn remove_output_redirect(
    chars: &[char],
    start: usize,
    out: &mut String,
    context: super::super::PathContext<'_>,
    targets: &mut Vec<String>,
    bounded_writes: &mut bool,
    temporary_writes: &mut bool,
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
    *bounded_writes &= bounded_write(&target, context);
    *temporary_writes &= super::super::chain_temporary::temporary_file_target(
        &target,
        context.home_dir,
        context.cwd,
    );
    targets.push(target);
    out.push(' ');
    Some(index)
}

pub(super) fn remove_quoted_heredoc(
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

pub(super) fn skip_heredoc_bodies(
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

pub(super) fn trailing_word(out: &str) -> &str {
    let start = out
        .rfind(|value: char| value.is_whitespace() || matches!(value, ';' | '|'))
        .map_or(0, |position| position + 1);
    &out[start..]
}

pub(super) fn boundary(value: Option<&char>) -> bool {
    value.is_none_or(|value| value.is_whitespace() || matches!(value, ';' | '|' | '&' | '<' | '>'))
}

#[cfg(test)]
#[path = "redirect_projection_tests.rs"]
mod tests;

#[cfg(all(test, unix))]
#[path = "redirect_scratch_tests.rs"]
mod scratch_tests;
