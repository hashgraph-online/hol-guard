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
//!
//! An interpreter is unbounded unless it is the whole command and the program
//! it runs, inline or fed on standard input, was read; it then runs only that
//! program, as it would run a script file.

use std::collections::BTreeSet;
use std::time::Instant;

use guard_contracts::NativeCommandObservationBatchV1;

use super::{rank, rule_floor, CompiledNativeCommandControls};
use crate::pretool::generic::workspace_redirects;
use crate::CanonicalCommandV1;

#[path = "native_command_link_makers.rs"]
mod link_makers;
#[path = "native_command_unmodeled_redirections.rs"]
mod redirections;
#[path = "native_command_unmodeled_shapes.rs"]
mod shapes;
use link_makers::creates_links;
use redirections::without_redirections;
use shapes::{data_heredocs, without_lookups, without_plain_awk};
pub(crate) use shapes::{python_is_builtin_only, python_stdin};

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
                .unmodeled_floor(command, context)
                .map(|floor| (NativeCommandObservationBatchV1::default(), Some(floor)))
                .ok_or(error),
            observed => observed.map(|batch| (batch, None)),
        }
    }

    /// The strongest floor of every active extension that could own part of
    /// the command, and never less than review. `None` keeps the evaluation
    /// failure.
    fn unmodeled_floor(
        &self,
        command: &CanonicalCommandV1,
        context: crate::pretool::PathContext<'_>,
    ) -> Option<&'static str> {
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
        // A lookup such as `command -v doctl` only prints a path: it never
        // runs the program it names, so it owns nothing.
        let looked = without_lookups(&command.normalized_text);
        let text = &looked;
        let heredocs = data_heredocs(text);
        let shell = match &heredocs {
            Some((shell, _)) => shell.clone(),
            None => shell_text(text).to_owned(),
        };
        // A redirection such as `;2>&1` is not a program. It goes before the
        // awk pass, which rejoins words with spaces: `2>&1` became `2 >& 1`,
        // and the lone fd then read as the program hiding the interpreter.
        let bare = without_plain_awk(&without_redirections(&shell));
        let shell = without_plain_awk(&shell);
        let shell = shell.as_str();
        let interpreted = named_words(&joined_quotes(&bare));
        // `source FILE` runs the file's words in this shell, so the file names
        // the programs the command can run. Reading it bounds those owners the
        // way a script file bounds an interpreter's. Until it was read, an
        // ordinary `source .venv/bin/activate && pytest -q` had no owner set at
        // all and was refused outright, with no approval left to give it.
        let sources_files = interpreted.contains("source") || interpreted.contains(".");
        let sourced = if sources_files {
            crate::pretool::sourced_program_sources(command, context)
                .filter(|texts| texts.iter().all(|text| bounds_its_owners(text)))
        } else {
            Some(Vec::new())
        };
        let sourced_resolved = sources_files && sourced.is_some();
        if shell.contains("$'")
            || shell.contains("$\"")
            || synthesizes_program(&unquoted_literal(shell), sourced_resolved)
        {
            return None;
        }
        let mut named = named_words(text);
        for source in sourced.iter().flatten() {
            named.extend(named_words(source));
        }
        if INTERPRETERS
            .iter()
            .any(|name| interpreted.contains(*name) && !(sourced_resolved && *name == "source"))
        {
            // A program read from a file names the tools it may launch
            // outside the command text, so it counts toward the owners.
            match crate::pretool::sole_program_sources(command, context) {
                Some(sources) => {
                    for source in sources {
                        named.extend(named_words(&source));
                    }
                }
                // Backgrounding or a redirect leaves no segments, so a module
                // launch such as `python3 -m http.server` looks like a script
                // that was never read. The module name is already in the
                // command.
                None if !interpreter_launch_reads_a_file(&bare) => {}
                None => return None,
            }
        }
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

/// `;2>&1 python3 evil.py` and the same shape with `<` or `>&`. A spaced
/// `cmd 2>&1` is not glued, and `python3 -` names no script file.
fn glued_redirect_runs_interpreter(text: &str) -> bool {
    let chars: Vec<char> = text.chars().collect();
    let mut glued = false;
    for index in 0..chars.len().saturating_sub(1) {
        if !matches!(chars[index], ';' | '|' | '&' | '\n' | '(') {
            continue;
        }
        // `&>`, `>&` and `<&` are one redirect. The `&` is not a separator.
        if chars[index] == '&'
            && (chars[index + 1] == '>' || (index > 0 && matches!(chars[index - 1], '>' | '<')))
        {
            continue;
        }
        let next = chars[index + 1];
        if matches!(next, '<' | '>') || (next == '&' && chars.get(index + 2) == Some(&'>')) {
            glued = true;
            break;
        }
        if !next.is_ascii_digit() {
            continue;
        }
        let rest = &chars[index + 1..];
        let end = rest
            .iter()
            .position(|value| value.is_whitespace())
            .unwrap_or(rest.len());
        if rest[..end].contains(&'>') || rest[..end].contains(&'<') {
            glued = true;
            break;
        }
    }
    if !glued {
        return false;
    }
    let words = named_words(text);
    words.iter().any(|word| {
        matches!(
            word.as_str(),
            "sh" | "bash"
                | "dash"
                | "zsh"
                | "python"
                | "python2"
                | "python3"
                | "node"
                | "ruby"
                | "perl"
                | "php"
        )
    }) && words.iter().any(|word| word.contains('.'))
}

/// Loops and conditionals, or one heredoc that only feeds standard input,
/// with nothing in the shell text that substitutes or overrides `PATH` and no
/// redirect except to a literal path.
fn reviewable_structure(command: &CanonicalCommandV1) -> bool {
    if command.path_overridden || command.confidence != "uncertain" {
        return false;
    }
    match command.uncertainty_reason.as_deref() {
        // Backgrounding runs the same programs the foreground text names, so
        // `npm start &` owns exactly what `npm start` owns. Without this arm a
        // trailing `&` blocked outright while the same command with a redirect
        // reached review, because the redirect reason wins the parser's scan.
        Some("background_job_not_yet_supported") => {
            let literal = unquoted_literal(&command.normalized_text);
            !background_pipeline(&command.normalized_text)
                && (!moves_data(&literal) || literal_redirects_only(&command.normalized_text))
        }
        Some("compound_shell_not_yet_supported") => {
            !moves_data(&unquoted_literal(&command.normalized_text))
                || literal_redirects_only(&command.normalized_text)
        }
        Some("command_redirect_not_yet_supported") => {
            let text = without_lookups(&command.normalized_text);
            // `;2>&1 python3 evil.py` has no segments: the redirect is the
            // uncertainty. Reviewing it would hide the interpreter.
            !glued_redirect_runs_interpreter(&text)
                && (input_heredoc(&text)
                    || literal_redirects_only(&text)
                    || data_heredocs(&text).is_some_and(|(shell, _)| plain_after_heredocs(&shell)))
        }
        // A lookup in a substitution is the only one that does not run a
        // program, so a command whose substitutions are all lookups reads
        // like any other compound command.
        Some("command_substitution_not_yet_supported") => {
            let text = without_lookups(&command.normalized_text);
            !text.contains("$(")
                && !text.contains('`')
                && !text.contains("<<")
                && plain_after_heredocs(&text)
        }
        _ => false,
    }
}

/// A command with its heredocs removed that moves no data, or only to
/// literal paths.
fn plain_after_heredocs(shell: &str) -> bool {
    !moves_data(&unquoted_literal(shell)) || literal_redirects_only(shell)
}

/// Every redirect names a literal path or is a quoted heredoc fed to `cat`,
/// or to `python3 -` as a builtin-only program, and
/// the rest substitutes nothing and, when a redirect names a file other than
/// `/dev/null`, makes no link that redirect could follow.
fn literal_redirects_only(text: &str) -> bool {
    workspace_redirects::project_naming_files(text).is_some_and(|(projected, names_files)| {
        // `2>&1>log` keeps the descriptor copy in the projected text. That
        // copy is not a file write, so it does not by itself move data.
        let projected = projected.replace("2>&1", " ").replace("2>/dev/null", " ");
        let literal = unquoted_literal(&projected);
        !(moves_data(&literal) || (names_files && creates_links(&literal)))
    })
}

/// A backgrounded pipeline stays out of the review floor. The pipe check
/// names a remote-code or exfiltration attack before this runs; anything it
/// cannot classify, including a benign pipe, keeps the evaluation failure.
/// A pipeline after the last backgrounded job runs in the foreground, as the
/// `curl -fsS http://localhost:8080/ | grep title` that checks a server just
/// started does.
fn background_pipeline(text: &str) -> bool {
    let preserve_backslash = cfg!(windows);
    let Ok(segments) =
        crate::parser_segments::split_pipelines_including_background(text, preserve_backslash)
    else {
        return text.contains('|');
    };
    let chars: Vec<char> = text.chars().collect();
    let last_job = segments
        .iter()
        .filter(|segment| {
            let mut rest = chars[segment.end..]
                .iter()
                .skip_while(|c| c.is_whitespace());
            rest.next() == Some(&'&') && rest.next() != Some(&'&')
        })
        .map(|segment| segment.end)
        .max()
        .unwrap_or(chars.len());
    segments
        .iter()
        .any(|segment| segment.pipeline_index > 0 && segment.start < last_job)
}

/// Whether shell text redirects, substitutes or sets the environment of a
/// command, such as `PATH`, outside single quotes.
fn moves_data(literal: &str) -> bool {
    literal.contains(['<', '>', '`'])
        || literal.contains("$(")
        || command_words(literal).any(|word| {
            (is_assignment(word) && !saves_job_pid(word))
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

/// An interpreter word followed by a program file, after redirections are
/// blanked. `python3 -m` and `node -e` are not file launches.
pub(crate) fn unread_file_interpreter(shell: &str) -> bool {
    const FILE_INTERPRETERS: &[&str] = &[
        "sh", "bash", "dash", "zsh", "python", "python2", "python3", "node", "ruby", "perl", "php",
    ];
    without_redirections(shell)
        .split(|character: char| {
            matches!(
                character,
                ';' | '&' | '|' | '(' | ')' | '{' | '}' | '\n' | '`'
            )
        })
        .any(|piece| {
            let words: Vec<&str> = piece
                .split_whitespace()
                .map(|word| word.trim_matches(['\'', '"']))
                .filter(|word| !word.is_empty() && !is_assignment(word))
                .skip_while(|word| SHELL_PREFIXES.contains(word))
                .collect();
            let Some(program) = words.first() else {
                return false;
            };
            if !FILE_INTERPRETERS.contains(&command_basename(program).as_str()) {
                return false;
            }
            for argument in &words[1..] {
                if matches!(*argument, "-c" | "-m" | "-e") {
                    return false;
                }
                if argument.starts_with('-') {
                    continue;
                }
                return true;
            }
            false
        })
}

/// Whether a backgrounded interpreter still names a program file this scan
/// did not read. A `python -m` module launch does not: the module is an
/// argument, same as the foreground command.
fn interpreter_launch_reads_a_file(shell: &str) -> bool {
    without_redirections(shell)
        .split(|character: char| {
            matches!(
                character,
                ';' | '&' | '|' | '(' | ')' | '{' | '}' | '\n' | '`'
            )
        })
        .any(command_reads_a_program_file)
}

fn command_reads_a_program_file(piece: &str) -> bool {
    let words: Vec<&str> = piece
        .split_whitespace()
        .map(|word| word.trim_matches(['\'', '"']))
        .filter(|word| !word.is_empty() && !is_assignment(word))
        .skip_while(|word| SHELL_PREFIXES.contains(word))
        .collect();
    let Some(program) = words.first() else {
        return false;
    };
    let program = command_basename(program);
    if !is_python(program.as_str()) {
        return INTERPRETERS.contains(&program.as_str());
    }
    !python_module_launch(&words[1..])
}

fn command_basename(word: &str) -> String {
    let base = word.rsplit(['/', '\\']).next().unwrap_or(word);
    base.strip_suffix(".exe")
        .unwrap_or(base)
        .to_ascii_lowercase()
}

fn is_python(name: &str) -> bool {
    name.strip_prefix("python").is_some_and(|version| {
        version
            .split('.')
            .all(|part| part.is_empty() || part.bytes().all(|byte| byte.is_ascii_digit()))
    })
}

/// `python -m module` before any script path, inline source, or stdin.
fn python_module_launch(arguments: &[&str]) -> bool {
    let mut index = 0;
    while index < arguments.len() {
        let argument = arguments[index];
        if argument == "-m" {
            return arguments.get(index + 1).is_some();
        }
        if argument == "-c" || argument == "-" || argument == "--" {
            return false;
        }
        if matches!(argument, "-W" | "-X" | "--check-hash-based-pycs") {
            index += 2;
            continue;
        }
        if argument.starts_with('-') {
            index += 1;
            continue;
        }
        return false;
    }
    false
}

/// Whether a sourced file's own words name every program it runs.
///
/// Reading a file bounds the owners only while its text is the whole story.
/// Text that builds a command word from an expansion or a glob, that sources
/// a further file this scan has not read, that hands text to an interpreter,
/// or that hides words behind an ANSI-C or locale quote can run a program
/// whose name never appears, so the command keeps the owners it had instead.
fn bounds_its_owners(text: &str) -> bool {
    if text.contains("$'") || text.contains("$\"") {
        return false;
    }
    let literal = mask_parameter_expansions(&unquoted_literal(text));
    !synthesizes_program(&literal, false)
        && !command_words(&mask_double_quoted_separators(&literal)).any(|word| {
            let base = command_basename(&joined_quotes(word));
            INTERPRETERS.contains(&base.as_str())
        })
}

/// The text with `${NAME}` parameter expansions replaced by a plain word.
///
/// The shell expands those to a value rather than running them, and a script
/// is full of them: `${BASH_SOURCE[0]:-$0}` inside a command substitution
/// would otherwise read as a command word built from an expansion. Bash's
/// `${ cmd; }` and `${| cmd; }` do run the commands they hold, so a brace
/// followed by a space or a pipe is left exactly as it stands, and `$(...)`
/// and backticks are never touched. A `${...}` whose body holds `$(...)` or
/// a backtick still runs that command, so the whole expansion is left in
/// place rather than hidden behind a plain word.
fn mask_parameter_expansions(literal: &str) -> String {
    let characters: Vec<char> = literal.chars().collect();
    let mut out = String::with_capacity(literal.len());
    let mut index = 0;
    while index < characters.len() {
        let expansion = characters[index] == '$'
            && characters.get(index + 1) == Some(&'{')
            && !matches!(
                characters.get(index + 2),
                Some(' ' | '\t' | '\n' | '|') | None
            );
        if !expansion || parameter_expansion_runs_a_command(&characters[index..]) {
            out.push(characters[index]);
            index += 1;
            continue;
        }
        out.push('x');
        index += 2;
        let mut depth = 1usize;
        while index < characters.len() && depth > 0 {
            match characters[index] {
                '{' => depth += 1,
                '}' => depth -= 1,
                _ => {}
            }
            index += 1;
        }
    }
    out
}

/// Bash runs a command substitution nested in a default value, as in
/// `${UNSET:-$(tool)}`. Masking the whole `${...}` would hide that program.
fn parameter_expansion_runs_a_command(characters: &[char]) -> bool {
    let mut depth = 1usize;
    let mut index = 2;
    while index < characters.len() && depth > 0 {
        if characters[index] == '`'
            || (characters[index] == '$' && characters.get(index + 1) == Some(&'('))
        {
            return true;
        }
        match characters[index] {
            '{' => depth += 1,
            '}' => depth -= 1,
            _ => {}
        }
        index += 1;
    }
    false
}

fn synthesizes_program(literal: &str, sourced: bool) -> bool {
    let masked = mask_double_quoted_separators(literal);
    let mut words = command_words(&masked).filter(|word| !is_assignment(word));
    words.any(|word| {
        !matches!(
            word,
            "for" | "case" | "select" | "in" | "done" | "fi" | "esac" | "[" | "[["
        ) && ((word == "." && !sourced) || word.contains(['$', '*', '?', '[']))
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

/// `server=$!`: the process ID of the job just backgrounded, saved so a later
/// `kill $server` stops it. A number moves no data, unless the name is one the
/// shell or loader reads.
fn saves_job_pid(word: &str) -> bool {
    word.split_once('=').is_some_and(|(name, value)| {
        value == "$!"
            && !matches!(
                name,
                "PATH" | "IFS" | "HOME" | "CDPATH" | "ENV" | "BASH_ENV" | "PS4" | "PROMPT_COMMAND"
            )
            && !name.starts_with("LD_")
            && !name.starts_with("DYLD_")
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

#[cfg(test)]
#[path = "native_command_unmodeled_sourced_tests.rs"]
mod sourced_tests;
