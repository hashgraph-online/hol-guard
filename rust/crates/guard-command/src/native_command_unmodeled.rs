//! Keep ordinary shell structure the canonical parser cannot model reviewable.
//!
//! Loops, conditionals, heredocs and redirects defeat the exact model that
//! extension matchers need. Treating that as an evaluation failure blocked
//! them outright, so a fully permitted `gh` call inside a `for` loop, a
//! `gh pr comment` fed by a heredoc, or `gh pr view 12 > pr.json` could not
//! even be approved. Those shapes are now treated like an uncertain
//! observation: they take the strongest floor of every active extension whose
//! programs the text names, or that cannot be recognized by name, and never
//! less than review.
//!
//! Everything that could hide a program or move data keeps the evaluation
//! failure: wrappers, nested executors, command substitution, redirects other
//! than one input heredoc or to a literal path, redirects after a program
//! that makes links, `PATH` overrides, interpreters and program names built
//! from expansions or globs, as do signed or managed policy and global
//! lockdown.

use std::collections::BTreeSet;
use std::time::Instant;

use guard_contracts::NativeCommandObservationBatchV1;

use super::{rank, rule_floor, CompiledNativeCommandControls};
use crate::pretool::generic::workspace_redirects;
use crate::CanonicalCommandV1;

#[path = "native_command_link_makers.rs"]
mod link_makers;
use link_makers::creates_links;

/// Compatibility owners recognize these programs without a catalog matcher.
const COMPATIBILITY_EXECUTABLES: &[(&str, &[&str])] = &[
    ("command.git", &["git"]),
    ("command.github", &["gh"]),
    ("command.container-runtime", &["docker"]),
    ("command.kubernetes-operations", &["kubectl", "oc"]),
    ("command.kubernetes-secrets", &["kubectl", "oc"]),
];

const UNMODELED_ERRORS: [&str; 2] = [
    "native_command_compatibility_model_unsupported",
    "native_command_compatibility_context_unsupported",
];

/// Programs that run text they receive, or a program named by a later
/// argument, so they can assemble any command.
const INTERPRETERS: &[&str] = &[
    "timeout",
    "gtimeout",
    "nice",
    "ionice",
    "sudo",
    "doas",
    "stdbuf",
    "chrt",
    "taskset",
    "setsid",
    "flock",
    "chroot",
    "strace",
    "ltrace",
    "unbuffer",
    "caffeinate",
    "fd",
    "-exec",
    "-execdir",
    "-ok",
    "-okdir",
    "sh",
    "bash",
    "zsh",
    "dash",
    "ksh",
    "csh",
    "tcsh",
    "fish",
    "ash",
    "busybox",
    "pwsh",
    "powershell",
    "cmd",
    "eval",
    "source",
    "exec",
    "xargs",
    "env",
    "python",
    "python2",
    "python3",
    "node",
    "deno",
    "bun",
    "perl",
    "ruby",
    "php",
    "lua",
    "osascript",
    "awk",
    "gawk",
    "watch",
    "parallel",
    "su",
    "script",
    "tmux",
    "screen",
    "expect",
];

/// Words that take a command position without being the program.
const SHELL_PREFIXES: &[&str] = &[
    "do", "then", "else", "elif", "while", "until", "if", "!", "time", "command", "builtin",
    "nohup",
];

impl CompiledNativeCommandControls {
    /// Observes `command`, returning the review floor it takes when it is
    /// unmodeled but its possible owners can still be bounded.
    pub(super) fn observe_command(
        &self,
        command: &CanonicalCommandV1,
        deadline: Option<Instant>,
        context: crate::pretool::PathContext<'_>,
        environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
    ) -> Result<(NativeCommandObservationBatchV1, Option<&'static str>), &'static str> {
        match self.program.observe_in(
            command,
            &self.active_extensions,
            deadline,
            context,
            environment,
        ) {
            Err(error) if UNMODELED_ERRORS.contains(&error) => self
                .unmodeled_floor(command)
                .map(|floor| (NativeCommandObservationBatchV1::default(), Some(floor)))
                .ok_or(error),
            observed => observed.map(|batch| (batch, None)),
        }
    }

    /// The strongest floor of every active extension that could own part of
    /// the command, and never less than review. `None` keeps the evaluation
    /// failure.
    fn unmodeled_floor(&self, command: &CanonicalCommandV1) -> Option<&'static str> {
        if self.global_block
            || self.binding.managed_revision != 0
            || self
                .binding
                .layers
                .iter()
                .any(|layer| layer.global_lockdown || layer.kind != "local-admin")
        {
            return None;
        }
        if !reviewable_structure(command) {
            return None;
        }
        let text = &command.normalized_text;
        let shell = shell_text(text);
        let interpreted = named_words(&joined_quotes(shell));
        if shell.contains("$'")
            || shell.contains("$\"")
            || synthesizes_program(&unquoted_literal(shell))
            || INTERPRETERS.iter().any(|name| interpreted.contains(*name))
        {
            return None;
        }
        let named = named_words(text);
        let mut floor = "review";
        for (index, extension) in self.program.extensions.iter().enumerate() {
            if !self.active_extensions.contains(&extension.extension_id) {
                continue;
            }
            let compatibility = COMPATIBILITY_EXECUTABLES
                .iter()
                .find(|(id, _)| *id == extension.extension_id)
                .map(|(_, executables)| *executables);
            let owns = self
                .program
                .extension_names(index, compatibility)
                .is_none_or(|names| names.is_empty() || !names.is_disjoint(&named));
            if owns && rank(self.extension_floor(index)) > rank(floor) {
                floor = self.extension_floor(index);
            }
        }
        Some(floor)
    }

    /// The floor the extension would apply to its strongest rule, as an
    /// uncertain observation owned by it would take.
    fn extension_floor(&self, index: usize) -> &'static str {
        let extension = &self.program.extensions[index];
        if self.blocked_extensions.contains(&extension.extension_id)
            || extension
                .permissions
                .iter()
                .any(|permission| self.blocked_permissions.contains(&permission.permission_id))
        {
            return "block";
        }
        self.program
            .rules
            .iter()
            .filter(|rule| rule.extension_index == index)
            .map(|rule| {
                if self
                    .explicitly_enabled_permissions
                    .contains(&rule.permission_id)
                {
                    "review"
                } else {
                    rule_floor(rule, extension.required)
                }
            })
            .max_by_key(|floor| rank(floor))
            .unwrap_or("review")
    }
}

/// Loops and conditionals, or one heredoc that only feeds standard input,
/// with nothing in the shell text that substitutes or overrides `PATH` and no
/// redirect except to a literal path.
fn reviewable_structure(command: &CanonicalCommandV1) -> bool {
    if command.path_overridden || command.confidence != "uncertain" {
        return false;
    }
    match command.uncertainty_reason.as_deref() {
        Some("compound_shell_not_yet_supported") => {
            !moves_data(&unquoted_literal(&command.normalized_text))
                || literal_redirects_only(&command.normalized_text)
        }
        Some("command_redirect_not_yet_supported") => {
            input_heredoc(&command.normalized_text)
                || literal_redirects_only(&command.normalized_text)
        }
        _ => false,
    }
}

/// Every redirect names a literal path or feeds `cat` a quoted heredoc, and
/// the rest substitutes nothing and, when a redirect names a file other than
/// `/dev/null`, makes no link that redirect could follow.
fn literal_redirects_only(text: &str) -> bool {
    workspace_redirects::project_naming_files(text).is_some_and(|(projected, names_files)| {
        let literal = unquoted_literal(&projected);
        !(moves_data(&literal) || (names_files && creates_links(&literal)))
    })
}

/// Whether shell text redirects, substitutes or sets the environment of a
/// command, such as `PATH`, outside single quotes.
fn moves_data(literal: &str) -> bool {
    literal.contains(['<', '>', '`'])
        || literal.contains("$(")
        || command_words(literal).any(|word| {
            is_assignment(word)
                || matches!(
                    word,
                    "export" | "declare" | "typeset" | "readonly" | "local" | "unset" | "alias"
                )
        })
}

/// One heredoc on the first line, ending the text, whose body cannot run
/// commands: its delimiter is quoted, or the body expands nothing.
fn input_heredoc(text: &str) -> bool {
    let Some((line, rest)) = text.split_once('\n') else {
        return false;
    };
    let Some((before, after)) = line.split_once("<<") else {
        return false;
    };
    let after = after.strip_prefix('-').unwrap_or(after).trim();
    let quoted = after.starts_with(['\'', '"']);
    let delimiter = after.trim_matches(['\'', '"']);
    if delimiter.is_empty()
        || !delimiter
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_')
        || moves_data(&unquoted_literal(before))
    {
        return false;
    }
    let mut lines: Vec<&str> = rest.lines().collect();
    if lines.pop().map(str::trim) != Some(delimiter)
        || lines.iter().any(|body| body.trim() == delimiter)
    {
        return false;
    }
    quoted || lines.iter().all(|body| !body.contains(['$', '`', '\\']))
}

/// Every word the shell could read as a program name or keyword token, with
/// and without quoting, as a full path, a basename and without a Windows
/// suffix, so `sh -c 'gh …'`, `g""h` and `C:\tools\GH.EXE` all name `gh`.
fn named_words(text: &str) -> BTreeSet<String> {
    let unquoted: String = text
        .chars()
        .filter(|character| !matches!(character, '\'' | '"' | '\\'))
        .collect();
    let mut named = BTreeSet::new();
    for value in [text, unquoted.as_str()] {
        let words = value.split(|character: char| {
            !(character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-' | '+' | '/'))
        });
        for word in words.chain(value.split_whitespace()) {
            let lowered = word.to_ascii_lowercase();
            let base = lowered
                .rsplit(['/', '\\'])
                .next()
                .unwrap_or_default()
                .to_owned();
            for name in [lowered, base] {
                if let Some(stem) = name
                    .strip_suffix(".exe")
                    .or_else(|| name.strip_suffix(".cmd"))
                {
                    named.insert(stem.to_owned());
                }
                if !name.is_empty() {
                    named.insert(name);
                }
            }
        }
    }
    named
}

/// The text with single-quoted spans reduced to their word characters.
/// Single-quoted text is literal, so its separators, redirects and expansions
/// are dropped, but its letters stay joined to the word around them as the
/// shell joins them: `'sh' -c` still names `sh` and `g''h` names `gh`.
/// Quotes inside double quotes or after a backslash stay ordinary text. An
/// unterminated quote or a heredoc, whose body quotes are not shell syntax,
/// keeps the whole text in view.
fn unquoted_literal(text: &str) -> String {
    if text.contains("<<") {
        return text.to_owned();
    }
    let mut literal = String::with_capacity(text.len());
    let (mut single, mut double, mut escaped) = (false, false, false);
    for character in text.chars() {
        if single {
            single = character != '\'';
            if single
                && (character.is_ascii_alphanumeric()
                    || matches!(character, '.' | '_' | '-' | '+' | '/'))
            {
                literal.push(character);
            }
        } else if escaped {
            escaped = false;
            literal.push(character);
        } else if character == '\'' && !double {
            single = true;
        } else {
            escaped = character == '\\';
            double ^= character == '"';
            literal.push(character);
        }
    }
    if single {
        return text.to_owned();
    }
    literal
}

/// The text the shell runs as commands. An accepted input heredoc contributes
/// only its command, since `input_heredoc` already keeps its body from
/// expanding and the body is data on standard input.
fn shell_text(text: &str) -> &str {
    match text.split_once('\n') {
        Some((line, _)) if text.contains("<<") => line.split_once("<<").map_or(line, |(b, _)| b),
        _ => text,
    }
}

/// The text with every quoted span reduced to its word characters, joined to
/// the word around it, so a quoted argument such as `--body "fix env
/// handling"` names no program while `"sh" -c` and `g""h` still do. A
/// backslash inside double quotes escapes the next character. An
/// unterminated quote keeps the whole text in view.
fn joined_quotes(text: &str) -> String {
    let mut joined = String::with_capacity(text.len());
    let (mut quote, mut escaped) = (None, false);
    for character in text.chars() {
        match quote {
            Some(_) if escaped => escaped = false,
            Some(open) if character == open => quote = None,
            Some(open) => {
                escaped = open == '"' && character == '\\';
                if character.is_ascii_alphanumeric()
                    || matches!(character, '.' | '_' | '-' | '+' | '/')
                {
                    joined.push(character);
                }
            }
            None if escaped => {
                escaped = false;
                joined.push(character);
            }
            None if matches!(character, '\'' | '"') => quote = Some(character),
            None => {
                escaped = character == '\\';
                joined.push(character);
            }
        }
    }
    if quote.is_some() {
        return text.to_owned();
    }
    joined
}

/// Whether a command position holds an expansion, glob or `.` source, which
/// can run a program whose name appears nowhere in the text.
fn synthesizes_program(literal: &str) -> bool {
    let masked = mask_double_quoted_separators(literal);
    let mut words = command_words(&masked).filter(|word| !is_assignment(word));
    words.any(|word| {
        !matches!(
            word,
            "for" | "case" | "select" | "in" | "done" | "fi" | "esac" | "[" | "[["
        ) && (word == "." || word.contains(['$', '*', '?', '[']))
    })
}

/// The text with command separators inside double quotes made ordinary, so a
/// quoted regex such as `"^@@|^[+-]"` stays one argument instead of starting
/// a fake command word. Expansion characters stay in place, so `"$cmd"` in a
/// command position is still seen, and a quoted span holding a command
/// substitution is left untouched because its commands still run. That
/// includes `$(...)`, backticks, and Bash's `${ cmd; }` / `${| cmd; }` form.
fn mask_double_quoted_separators(literal: &str) -> String {
    let mut out = String::with_capacity(literal.len());
    let mut span: Option<String> = None;
    let mut escaped = false;
    for character in literal.chars() {
        let Some(quoted) = span.as_mut() else {
            out.push(character);
            if escaped {
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == '"' {
                span = Some(String::new());
            }
            continue;
        };
        if escaped {
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else if character == '"' {
            out.push_str(&mask_span(quoted));
            out.push(character);
            span = None;
            continue;
        }
        quoted.push(character);
    }
    if let Some(quoted) = span {
        out.push_str(&quoted);
    }
    out
}

fn span_runs_a_command(quoted: &str) -> bool {
    quoted.contains("$(")
        || quoted.contains('`')
        || quoted.match_indices("${").any(|(at, _)| {
            quoted[at + 2..]
                .chars()
                .next()
                .is_some_and(|character| character.is_whitespace() || character == '|')
        })
}

fn mask_span(quoted: &str) -> String {
    if span_runs_a_command(quoted) {
        return quoted.to_owned();
    }
    quoted
        .chars()
        .map(|character| match character {
            ';' | '&' | '|' | '(' | ')' | '{' | '}' | '\n' => 'x',
            other => other,
        })
        .collect()
}

/// The leading assignments and first word of each simple command, after
/// any shell keyword that takes a command position.
fn command_words(literal: &str) -> impl Iterator<Item = &str> {
    literal
        .split(|character: char| {
            matches!(
                character,
                ';' | '&' | '|' | '(' | ')' | '{' | '}' | '\n' | '`'
            )
        })
        .flat_map(|piece| {
            let words = piece
                .split_whitespace()
                .skip_while(|word| SHELL_PREFIXES.contains(word));
            let mut leading = Vec::new();
            for word in words {
                leading.push(word);
                if !is_assignment(word) {
                    break;
                }
            }
            leading
        })
}

fn is_assignment(word: &str) -> bool {
    word.split_once('=').is_some_and(|(name, _)| {
        !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    })
}

#[cfg(test)]
#[path = "native_command_unmodeled_tests.rs"]
mod tests;
