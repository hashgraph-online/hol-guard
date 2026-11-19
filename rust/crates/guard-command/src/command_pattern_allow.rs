//! Guard Cloud Allow rules that name a command pattern instead of one exact
//! command.
//!
//! A person who approves `gh pr view 7276 --repo owner/name` in Guard Cloud
//! usually means "this program with these arguments, whatever the PR number".
//! An exact rule never matches the next call, so the rule may replace some
//! arguments with `*`. Such a rule only ever allows, and only within limits
//! that keep a wildcard from naming more than the person read:
//!
//! - the pattern is one condition, `exact`, `startsWith` or `glob`, matched
//!   case-sensitively, whose only wildcard is `*` (`?` and `[` must be
//!   escaped);
//! - the program and the word after it are plain literal words (no quotes,
//!   escapes, expansions or wildcards), so `git *`, `* status` or
//!   `bash '-c' *` cannot be written. A wrapper that runs another program
//!   (`env`, `sudo`, `xargs`, `npx`, ...) cannot be the program at all, an
//!   interpreter cannot be followed by an option (`bash -c *`, `cmd /c *`),
//!   and a tool cannot be followed by the subcommand that runs a program or
//!   code it is given (`npm exec *`, `deno eval *`, `uv run *`);
//! - the command it allows is one simple command: no unquoted `;`, `&`, `|`,
//!   `<`, `>`, parentheses, comments or line breaks, and no `$` expansion or
//!   command substitution outside single quotes, and no whitespace the shell
//!   would not split on. A `*` that would otherwise cover `x; curl … | sh`
//!   matches nothing;
//! - a `startsWith` prefix ends at a word boundary, and a git pattern never
//!   covers an option that runs a program it names (`--receive-pack`,
//!   `--upload-pack`, `rebase -x`, ...).
//!
//! Block and review rules keep the exact-command form, which matches every
//! spelling of a command; a pattern only narrows what a person must approve.

use guard_contracts::{CommandConditionV1, CommandExpressionV1};

use crate::command_expression_match::{normalize_command_text, validate_expression};

#[cfg(test)]
#[path = "command_pattern_allow_tests.rs"]
mod tests;

/// Programs that run another program named in their arguments, so a pattern
/// that starts with one could allow anything.
const WRAPPERS: &[&str] = &[
    "builtin",
    "bunx",
    "busybox",
    "caffeinate",
    "chroot",
    "chronic",
    "command",
    "doas",
    "env",
    "eval",
    "exec",
    "faketime",
    "flock",
    "ionice",
    "ltrace",
    "nice",
    "nohup",
    "npx",
    "parallel",
    "pkexec",
    "pnpx",
    "runuser",
    "script",
    "setsid",
    "stdbuf",
    "strace",
    "su",
    "sudo",
    "systemd-run",
    "taskset",
    "time",
    "timeout",
    "unbuffer",
    "uvx",
    "watch",
    "xargs",
];

/// Subcommands that run a program, script or code given in the words after
/// them, so `npm exec *` could allow anything. These programs may not start
/// with an option either, or the wildcard could supply the subcommand
/// (`npm --silent exec *`) or a setting that runs code (`git -c *`).
const RUNNER_SUBCOMMANDS: &[(&str, &[&str])] = &[
    ("bun", &["exec", "run", "x"]),
    ("conda", &["run"]),
    ("deno", &["eval", "run"]),
    (
        "git",
        &[
            "bisect",
            "config",
            "difftool",
            "filter-branch",
            "instaweb",
            "mergetool",
            "send-email",
            "submodule",
        ],
    ),
    ("go", &["run"]),
    ("hatch", &["run"]),
    ("mise", &["exec", "x"]),
    ("npm", &["exec", "x"]),
    ("pdm", &["run"]),
    ("pipenv", &["run"]),
    ("pipx", &["run"]),
    ("pnpm", &["dlx", "exec"]),
    ("poetry", &["run"]),
    ("uv", &["run", "tool"]),
    ("yarn", &["dlx", "exec"]),
];

/// Subcommands that run a package script the next word names, so the script
/// name must stay literal: `npm run test *` is a pattern, `npm run *` would let
/// the wildcard pick any script.
const SCRIPT_RUNNERS: &[(&str, &[&str])] = &[
    ("npm", &["rum", "run", "run-script", "urn"]),
    ("pnpm", &["run", "run-script"]),
    ("yarn", &["run"]),
];

/// Package managers that read their own options anywhere before a bare `--`,
/// some of which choose the shell or Node options a script runs with.
const PACKAGE_MANAGERS: &[&str] = &["npm", "pnpm", "yarn"];

/// Long git options that run a program, load hooks or settings, or write a
/// file the command names. Git accepts any unambiguous prefix of a long
/// option (`--rec` for `--receive-pack`), so every prefix is refused too.
const GIT_EXEC_LONG_OPTIONS: &[&str] = &[
    "config",
    "exec",
    "exec-path",
    "extcmd",
    "open-files-in-pager",
    "output",
    "receive-pack",
    "template",
    "upload-pack",
];

/// Short git options, by subcommand, that do the same (`clone -u`,
/// `rebase -x`, `grep -O`).
const GIT_EXEC_SHORT_OPTIONS: &[(&str, &[char])] = &[
    ("archive", &['o']),
    ("clone", &['c', 'u']),
    ("grep", &['O']),
    ("ls-remote", &['u']),
    ("rebase", &['x']),
];

/// Interpreters whose code-running switches start with `/` (`cmd /c`).
const SLASH_SWITCH_INTERPRETERS: &[&str] = &["cmd", "powershell", "pwsh"];

/// Programs that run code passed as an option (`-c`, `-e`, `--eval`), so the
/// word after them must be a literal non-option such as a script path.
const INTERPRETERS: &[&str] = &[
    "ash",
    "bash",
    "bun",
    "cmd",
    "csh",
    "dash",
    "deno",
    "fish",
    "ksh",
    "lua",
    "node",
    "nodejs",
    "osascript",
    "perl",
    "php",
    "powershell",
    "pwsh",
    "python",
    "python2",
    "python3",
    "ruby",
    "sh",
    "tcsh",
    "zsh",
];

/// A validated pattern Allow: the expression and the program it names.
#[derive(Debug, Clone, PartialEq)]
pub struct CommandPatternAllow {
    pub expression: CommandExpressionV1,
    pub program: String,
}

/// The program a pattern Allow names, or the code that refuses it.
pub fn validate_allow_pattern(expression: &CommandExpressionV1) -> Result<String, String> {
    if expression.combinator != "all" || expression.conditions.len() != 1 {
        return Err("command_pattern_allow_single_condition".to_owned());
    }
    validate_expression(expression)?;
    let condition = &expression.conditions[0];
    if !condition.case_sensitive {
        return Err("command_pattern_allow_case_sensitive".to_owned());
    }
    let value = normalize_command_text(&condition.value)?;
    let words: Vec<&str> = value.split(' ').collect();
    match condition.operator.as_str() {
        "exact" => {}
        "startsWith" => literal_head(&words)?,
        "glob" => {
            only_star_wildcards(&value)?;
            literal_head(&words)?;
        }
        _ => return Err("command_pattern_allow_operator".to_owned()),
    }
    let program = words[0];
    if program.contains(['*', '?', '[', '\\', '=', '$', '`', '\'', '"']) {
        return Err("command_pattern_allow_program_literal".to_owned());
    }
    let base = program_base(program);
    if condition.operator != "exact" {
        if WRAPPERS.contains(&base.as_str()) {
            return Err("command_pattern_allow_wrapper".to_owned());
        }
        let option = words[1].starts_with('-')
            || words[1].starts_with('/') && SLASH_SWITCH_INTERPRETERS.contains(&base.as_str());
        if INTERPRETERS.contains(&base.as_str()) && option {
            return Err("command_pattern_allow_interpreter_option".to_owned());
        }
        if RUNNER_SUBCOMMANDS.iter().any(|(runner, subcommands)| {
            *runner == base && (words[1].starts_with('-') || subcommands.contains(&words[1]))
        }) {
            return Err("command_pattern_allow_runner".to_owned());
        }
        let runs_script = SCRIPT_RUNNERS
            .iter()
            .any(|(runner, subcommands)| *runner == base && subcommands.contains(&words[1]));
        if runs_script
            && !words
                .get(2)
                .is_some_and(|script| plain_word(script) && !script.starts_with('-'))
        {
            return Err("command_pattern_allow_runner".to_owned());
        }
    }
    Ok(program.to_owned())
}

fn plain_word(word: &str) -> bool {
    let word = word.strip_prefix("~/").unwrap_or(word);
    !word.is_empty()
        && word
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._/@+=,:-".contains(&byte))
}

/// The program and the word after it are plain words the shell passes through
/// unchanged: no wildcard, quote, escape, expansion (`%VAR%` in CMD
/// included) or brace. A leading `~/`
/// (the home folder, which one simple command cannot change) is the one
/// expansion allowed.
fn literal_head(words: &[&str]) -> Result<(), String> {
    if words.len() < 2 || !words[..2].iter().all(|word| plain_word(word)) {
        return Err("command_pattern_allow_literal_head".to_owned());
    }
    Ok(())
}

/// `*` is the one wildcard; `?` and `[` must be escaped with a backslash.
fn only_star_wildcards(value: &str) -> Result<(), String> {
    let mut characters = value.chars();
    while let Some(character) = characters.next() {
        match character {
            '\\' => {
                characters.next();
            }
            '?' | '[' => return Err("command_pattern_allow_wildcard".to_owned()),
            _ => {}
        }
    }
    Ok(())
}

/// The program's file name, lowercased, without a Windows `.exe` suffix or a
/// trailing version (`python3.12` reads as `python3`).
fn program_base(program: &str) -> String {
    let name = program.rsplit(['/', '\\']).next().unwrap_or(program);
    let name = name.to_ascii_lowercase();
    let name = name.strip_suffix(".exe").unwrap_or(&name).to_owned();
    match name.find('.') {
        Some(dot)
            if name[dot + 1..]
                .bytes()
                .all(|byte| byte.is_ascii_digit() || byte == b'.') =>
        {
            name[..dot].to_owned()
        }
        _ => name,
    }
}

/// Whether `command` is one simple command: nothing that chains, pipes,
/// redirects, groups or substitutes another command, no comment that hides
/// the rest of the line, no `$` expansion outside single quotes, and no line
/// break.
pub fn is_simple_command(command: &str) -> bool {
    let mut characters = command.chars().peekable();
    let mut single = false;
    let mut double = false;
    let mut word_start = true;
    // The shell splits words only at a space or a tab, but matching reads
    // every whitespace character as a separator: a vertical tab, form feed or
    // no-break space would let `x.sh\u{b}evil` match a pattern for `x.sh *`.
    if command.chars().any(|character| {
        (character.is_control() || character.is_whitespace()) && !matches!(character, ' ' | '\t')
    }) {
        return false;
    }
    while let Some(character) = characters.next() {
        let at_word_start =
            std::mem::replace(&mut word_start, character == ' ' || character == '\t');
        if single {
            single = character != '\'';
            continue;
        }
        match character {
            '`' | '$' => return false,
            '#' if at_word_start && !double => return false,
            '\\' => {
                // An escaped line break continues the line; anything else
                // escaped is a literal character.
                if matches!(characters.next(), None | Some('\n' | '\r')) {
                    return false;
                }
            }
            '"' => double = !double,
            '\'' if !double => single = true,
            ';' | '&' | '|' | '<' | '>' | '(' | ')' if !double => return false,
            _ => {}
        }
    }
    !single && !double
}

/// Whether `pattern` allows `command`: a simple command whose program is the
/// pattern's literal program and which the expression matches.
pub fn allows(pattern: &CommandPatternAllow, command: &str) -> bool {
    allows_on(pattern, command, cfg!(windows))
}

/// [`allows`], where `cmd_may_run` says whether CMD may run the command.
/// CMD expands `%VAR%` and `!VAR!` everywhere, treats `^` as an escape, and
/// does not treat single quotes as quotes, so `git push 'a&whoami'` runs
/// `whoami` there; a command with any of those characters never matches.
fn allows_on(pattern: &CommandPatternAllow, command: &str, cmd_may_run: bool) -> bool {
    if !is_simple_command(command)
        || cmd_may_run && command.contains(['%', '!', '^', '&', '|', '<', '>'])
        || normalize_command_text(command).is_err()
    {
        return false;
    }
    let normalized = normalize_words(command);
    if normalized.split(' ').next() != Some(pattern.program.as_str()) {
        return false;
    }
    let condition = &pattern.expression.conditions[0];
    if condition.operator != "exact"
        && program_base(&pattern.program) == "git"
        && git_runs_given_program(&shell_words(&normalized))
    {
        return false;
    }
    if condition.operator != "exact"
        && PACKAGE_MANAGERS.contains(&program_base(&pattern.program).as_str())
        && adds_package_manager_option(
            &shell_words(&normalized),
            &shell_words(&normalize_words(&condition.value)),
        )
    {
        return false;
    }
    let value = normalize_words(&condition.value);
    match condition.operator.as_str() {
        "exact" => normalized == value,
        // A prefix ends at a word boundary: `startsWith "x.sh"` allows
        // `x.sh 1`, not `x.sh.evil`.
        "startsWith" => normalized == value || normalized.starts_with(&format!("{value} ")),
        "glob" => glob_matches(&value, &normalized),
        _ => false,
    }
}

/// `text` with each run of whitespace between words collapsed to one space,
/// and quoted text kept as written: `'safe  file'` and `'safe file'` name
/// different files, so they must not compare equal.
fn normalize_words(text: &str) -> String {
    let mut normalized = String::with_capacity(text.len());
    let mut single = false;
    let mut double = false;
    let mut pending_space = false;
    let mut characters = text.trim().chars();
    while let Some(character) = characters.next() {
        if !single && !double && character.is_whitespace() {
            pending_space = true;
            continue;
        }
        if pending_space {
            normalized.push(' ');
            pending_space = false;
        }
        normalized.push(character);
        if single {
            single = character != '\'';
            continue;
        }
        match character {
            '\\' => {
                if let Some(escaped) = characters.next() {
                    normalized.push(escaped);
                }
            }
            '"' => double = !double,
            '\'' if !double => single = true,
            _ => {}
        }
    }
    normalized
}

/// Whether a glob whose only wildcard is `*` (backslash escapes a literal)
/// matches all of `text`. The literal pieces are found left to right, so the
/// match is linear in the length of `text`.
fn glob_matches(pattern: &str, text: &str) -> bool {
    let mut pieces = vec![String::new()];
    let mut characters = pattern.chars();
    while let Some(character) = characters.next() {
        match character {
            '\\' => pieces
                .last_mut()
                .expect("pieces is never empty")
                .extend(characters.next()),
            '*' => pieces.push(String::new()),
            _ => pieces
                .last_mut()
                .expect("pieces is never empty")
                .push(character),
        }
    }
    let first = &pieces[0];
    if pieces.len() == 1 {
        return text == first;
    }
    let last = &pieces[pieces.len() - 1];
    if !text.starts_with(first.as_str())
        || text.len() < first.len() + last.len()
        || !text.ends_with(last.as_str())
    {
        return false;
    }
    let end = text.len() - last.len();
    let mut cursor = first.len();
    for piece in &pieces[1..pieces.len() - 1] {
        match text[cursor..end].find(piece.as_str()) {
            Some(found) => cursor += found + piece.len(),
            None => return false,
        }
    }
    true
}

/// Whether a package manager command passes an option, before a bare `--`,
/// more often than the pattern names it word for word. npm reads options such
/// as `--script-shell` and `--node-options` there, accepts abbreviations of
/// them, and keeps the last of a repeated option, so a wildcard must not be
/// able to supply or repeat any option the package manager reads. Words after
/// `--` go to the script.
fn adds_package_manager_option(words: &[String], pattern_words: &[String]) -> bool {
    let options: Vec<&String> = words
        .iter()
        .skip(1)
        .take_while(|word| word.as_str() != "--")
        .filter(|word| word.starts_with('-'))
        .collect();
    options.iter().any(|option| {
        let used = options.iter().filter(|other| *other == option).count();
        let named = pattern_words.iter().filter(|word| word == option).count();
        used > named
    })
}

/// Whether a git command's words carry an option that runs a program or code
/// they name, as `git push --receive-pack='sh -c id' .` does. An exact rule
/// names the option, so only a wildcard or prefix is checked.
fn git_runs_given_program(words: &[String]) -> bool {
    let subcommand = words.get(1).map(String::as_str).unwrap_or_default();
    let short: &[char] = GIT_EXEC_SHORT_OPTIONS
        .iter()
        .find(|(name, _)| *name == subcommand)
        .map_or(&[], |(_, letters)| letters);
    words.iter().skip(1).any(|word| {
        if let Some(long) = word.strip_prefix("--") {
            let name = long.split('=').next().unwrap_or_default();
            return !name.is_empty()
                && GIT_EXEC_LONG_OPTIONS
                    .iter()
                    .any(|option| option.starts_with(name));
        }
        word.strip_prefix('-')
            .is_some_and(|cluster| cluster.chars().any(|letter| short.contains(&letter)))
    })
}

/// The words of a simple command as the shell passes them on: quotes and
/// escapes removed.
fn shell_words(command: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut word = String::new();
    let mut started = false;
    let mut single = false;
    let mut double = false;
    let mut characters = command.chars();
    while let Some(character) = characters.next() {
        if single {
            if character == '\'' {
                single = false;
            } else {
                word.push(character);
            }
            continue;
        }
        match character {
            '\'' if !double => {
                single = true;
                started = true;
            }
            '"' => {
                double = !double;
                started = true;
            }
            '\\' => {
                let escaped = characters.next().unwrap_or_default();
                if double && !matches!(escaped, '"' | '\\' | '$' | '`') {
                    word.push('\\');
                }
                word.push(escaped);
                started = true;
            }
            ' ' | '\t' if !double => {
                if started {
                    words.push(std::mem::take(&mut word));
                    started = false;
                }
            }
            _ => {
                word.push(character);
                started = true;
            }
        }
    }
    if started {
        words.push(word);
    }
    words
}

/// A pattern Allow read from a policy document's `match.commands` object.
pub fn parse_allow_pattern(value: &serde_json::Value) -> Result<CommandPatternAllow, String> {
    let object = value
        .as_object()
        .ok_or_else(|| "command_expression_must_be_object".to_owned())?;
    let combinator = object
        .get("combinator")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "command_expression_combinator_required".to_owned())?;
    let conditions = object
        .get("conditions")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| "command_expression_conditions_required".to_owned())?;
    let conditions = conditions
        .iter()
        .map(|condition| {
            if condition.get("field").and_then(serde_json::Value::as_str) != Some("command") {
                return Err("unsupported_command_condition_field".to_owned());
            }
            Ok(CommandConditionV1 {
                operator: condition
                    .get("operator")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default()
                    .to_owned(),
                value: condition
                    .get("value")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default()
                    .to_owned(),
                case_sensitive: condition
                    .get("caseSensitive")
                    .and_then(serde_json::Value::as_bool)
                    .unwrap_or(false),
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let expression = CommandExpressionV1 {
        combinator: combinator.to_owned(),
        conditions,
    };
    let program = validate_allow_pattern(&expression)?;
    Ok(CommandPatternAllow {
        expression,
        program,
    })
}
