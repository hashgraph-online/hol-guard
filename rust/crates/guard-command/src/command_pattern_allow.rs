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
//!   command substitution outside single quotes. A `*` that would otherwise
//!   cover `x; curl … | sh` matches nothing.
//!
//! Block and review rules keep the exact-command form, which matches every
//! spelling of a command; a pattern only narrows what a person must approve.

use guard_contracts::{CommandConditionV1, CommandExpressionV1};

use crate::command_expression_match::{
    matches_expression, normalize_command_text, validate_expression,
};

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
/// them, so `npm exec *` could allow anything.
const RUNNER_SUBCOMMANDS: &[(&str, &[&str])] = &[
    ("bun", &["exec", "run", "x"]),
    ("conda", &["run"]),
    ("deno", &["eval", "run"]),
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
        if RUNNER_SUBCOMMANDS
            .iter()
            .any(|(runner, subcommands)| *runner == base && subcommands.contains(&words[1]))
        {
            return Err("command_pattern_allow_runner".to_owned());
        }
    }
    Ok(program.to_owned())
}

/// The program and the word after it are plain words the shell passes through
/// unchanged: no wildcard, quote, escape, expansion or brace.
fn literal_head(words: &[&str]) -> Result<(), String> {
    let plain = |word: &&str| {
        !word.is_empty()
            && word
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._/@%+=,:-".contains(&byte))
    };
    if words.len() < 2 || !words[..2].iter().all(plain) {
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
    while let Some(character) = characters.next() {
        let at_word_start =
            std::mem::replace(&mut word_start, character == ' ' || character == '\t');
        if matches!(character, '\n' | '\r' | '\0') {
            return false;
        }
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
    if !is_simple_command(command) {
        return false;
    }
    let Ok(normalized) = normalize_command_text(command) else {
        return false;
    };
    if normalized.split(' ').next() != Some(pattern.program.as_str()) {
        return false;
    }
    matches_expression(&pattern.expression, &normalized).unwrap_or(false)
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
