//! Side-effect-free shell token and transparent wrapper parsing
//! (`runtime/command_tokens.py`, 154 lines — verbatim).

use crate::env_wrapper::parse_env_wrapper;

const SUDO_OPTIONS_WITH_VALUES: &[&str] =
    &["-C", "-D", "-g", "-h", "-p", "-R", "-r", "-T", "-t", "-u"];
const SUDO_LONG_OPTIONS_WITH_VALUES: &[&str] = &[
    "--chdir",
    "--chroot",
    "--close-from",
    "--command-timeout",
    "--group",
    "--host",
    "--login-class",
    "--prompt",
    "--role",
    "--type",
    "--user",
];

/// `executable_name` (:30-33).
pub fn executable_name(value: Option<&str>) -> Option<String> {
    let value = value?;
    Some(
        value
            .replace('\\', "/")
            .rsplit('/')
            .next()
            .unwrap_or("")
            .to_lowercase(),
    )
}

/// Unquoted backslashes stay literal in a Windows command so a Git Bash line
/// can name `C:\Users\dev` without escaping every separator. A backslash in
/// front of one of these operators is the one place that reading can be wrong:
/// no path component starts with `;`, `&`, `|`, `<`, `>`, `(` or `)`, so the
/// author may mean the POSIX escape. `find … -exec grep -l pattern {} \;` ends
/// every `-exec` body that way, and reading the `;` as a separator throws the
/// `find` arguments away and leaves a command no parser can model.
/// `escapes_shell_operator` decides when that reading is safe to take.
pub(crate) const SHELL_OPERATORS: &[char] = &[';', '&', '|', '<', '>', '(', ')'];

/// How many characters of `rest` are one redirection, such as `2>/dev/null`,
/// `>out.txt`, `>> log` or `2>&1`, or `None` when `rest` does not start one.
/// A redirection names no program, so no reading of the text can run a command
/// through it. A target that starts with a shell operator, the way bash's
/// `>(cat)` starts a process substitution, is not read as one.
fn redirection_length(rest: &[char]) -> Option<usize> {
    let mut index = usize::from(rest.first().is_some_and(char::is_ascii_digit));
    let arrow = *rest.get(index)?;
    if arrow != '>' && arrow != '<' {
        return None;
    }
    index += 1;
    if rest.get(index) == Some(&arrow) {
        index += 1;
    }
    if rest.get(index) == Some(&'&') {
        index += 1;
        let digits = rest[index..]
            .iter()
            .take_while(|value| value.is_ascii_digit())
            .count();
        return (digits > 0).then_some(index + digits);
    }
    while matches!(rest.get(index), Some(' ' | '\t')) {
        index += 1;
    }
    let target = rest[index..]
        .iter()
        .take_while(|value| !value.is_whitespace() && !SHELL_OPERATORS.contains(*value))
        .count();
    // A quote, backtick or `$` lets a shell read an operator inside the target,
    // so the scan above could stop short of where the shell does.
    if rest[index..index + target]
        .iter()
        .any(|value| matches!(value, '"' | '\'' | '`' | '$'))
    {
        return None;
    }
    (target > 0).then_some(index + target)
}

/// Whether an unquoted `\` escapes the operator that starts `rest` while
/// backslashes are otherwise kept literal. `false` keeps the backslash literal
/// and lets the operator act as one.
///
/// A Windows agent may run this text in PowerShell or cmd, where `\` is never
/// an escape: `echo hi \; Remove-Item C:\Users\dev` runs `Remove-Item` there.
/// The escape is read only where both readings name the same programs, which is
/// when no command word follows the operator: the text ends, a real `;`, `|`,
/// `&` or newline starts the next command, or only redirections such as
/// `2>/dev/null` separate the operator from one of those. Anything else,
/// including a bare carriage return PowerShell may read as a line break, keeps
/// the literal reading, so the operator still splits the line and every word
/// after it is reviewed as a command.
pub(crate) fn escapes_shell_operator(rest: &[char]) -> bool {
    let Some((operator, after)) = rest.split_first() else {
        return false;
    };
    if !SHELL_OPERATORS.contains(operator) {
        return false;
    }
    let mut rest = after;
    loop {
        let blanks = rest
            .iter()
            .take_while(|value| matches!(value, ' ' | '\t'))
            .count();
        rest = &rest[blanks..];
        match rest.first() {
            None => return true,
            Some(';' | '|' | '&' | '\n') => return true,
            _ => {}
        }
        let Some(length) = redirection_length(rest) else {
            return false;
        };
        rest = &rest[length..];
    }
}

/// Whether the unquoted `\` at `backslash` in `chars` escapes the operator
/// after it. Bash pairs a run of backslashes off from the left, so only the
/// backslash that ends an odd-length run escapes anything: in `job \\&` the
/// pair is one literal backslash and the `&` still backgrounds the command.
pub(crate) fn backslash_escapes_operator(chars: &[char], backslash: usize) -> bool {
    let run = chars[..backslash]
        .iter()
        .rev()
        .take_while(|value| **value == '\\')
        .count();
    run % 2 == 0 && escapes_shell_operator(&chars[backslash + 1..])
}

/// `_windows_shell_tokens` (:36-92). Quoted POSIX escapes preserved; unquoted
/// path separators kept literal, apart from the escaped shell operators above.
#[allow(dead_code)]
pub fn windows_shell_tokens(command: &str) -> (Vec<String>, bool) {
    let mut tokens: Vec<String> = Vec::new();
    let mut token: Vec<char> = Vec::new();
    let mut started = false;
    let mut quote = '\0';
    let mut escaped = false;
    let chars: Vec<char> = command.chars().collect();
    let mut index = 0usize;
    while index < chars.len() {
        let current = chars[index];
        index += 1;
        if escaped {
            if quote == '"' && !['"', '\\', '$', '`'].contains(&current) {
                token.push('\\');
            }
            token.push(current);
            started = true;
            escaped = false;
            continue;
        }
        if quote == '\'' {
            if current == '\'' {
                quote = '\0';
            } else {
                token.push(current);
                started = true;
            }
            continue;
        }
        if quote == '"' {
            if current == '"' {
                quote = '\0';
            } else if current == '\\' {
                escaped = true;
                started = true;
            } else {
                token.push(current);
                started = true;
            }
            continue;
        }
        if current == '\'' {
            quote = '\'';
            started = true;
        } else if current == '"' {
            quote = '"';
            started = true;
        } else if current == '\\' {
            if backslash_escapes_operator(&chars, index - 1) {
                token.push(chars[index]);
                index += 1;
            } else {
                token.push('\\');
            }
            started = true;
        } else if " \t\r\n".contains(current) {
            if started {
                tokens.push(token.iter().collect());
                token.clear();
                started = false;
            }
        } else {
            token.push(current);
            started = true;
        }
    }
    if quote != '\0' || escaped {
        // Python raises ValueError; caller's split() fallback applies.
        return (
            command.split_whitespace().map(str::to_owned).collect(),
            false,
        );
    }
    if started {
        tokens.push(token.iter().collect());
    }
    (tokens, true)
}

/// `shell_tokens` (:95-103) → `(tokens, exact)`.
pub fn shell_tokens(command: &str) -> (Vec<String>, bool) {
    if cfg!(windows) {
        return windows_shell_tokens(command);
    }
    match crate::parser_segments::shell_tokens_preserving_redirects(command) {
        Ok(tokens) => (tokens, true),
        Err(_) => (
            command.split_whitespace().map(str::to_owned).collect(),
            false,
        ),
    }
}

/// `_ENV_ASSIGNMENT_PATTERN.fullmatch` — `^[A-Za-z_][A-Za-z0-9_]*=.*$` DOTALL.
pub(crate) fn env_assignment_name(token: &str) -> Option<&str> {
    let eq = token.find('=')?;
    let name = &token[..eq];
    if name.is_empty() {
        return None;
    }
    let mut chars = name.chars();
    let first = chars.next()?;
    if !(first.is_ascii_alphabetic() || first == '_') {
        return None;
    }
    if !chars.all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return None;
    }
    Some(name)
}

/// `leading_environment` (:106-133) → `(names, executable_index, wrappers)`.
pub fn leading_environment(tokens: &[String]) -> (Vec<String>, usize, Vec<String>) {
    let mut names: Vec<String> = Vec::new();
    let mut wrappers: Vec<String> = Vec::new();
    let mut index = 0usize;
    while index < tokens.len() {
        while env_assignment_name(&tokens[index]).is_some() {
            names.push(env_assignment_name(&tokens[index]).unwrap().to_owned());
            index += 1;
            if index >= tokens.len() {
                return (names, index, wrappers);
            }
        }
        let executable = executable_name(Some(&tokens[index]));
        if executable.as_deref() == Some("env") {
            let parsed = parse_env_wrapper(&tokens[index + 1..], None, None);
            if parsed.complete && parsed.command_index.is_none() {
                break;
            }
            wrappers.push("env".to_owned());
            names.extend(
                parsed
                    .environment_delta
                    .assignments
                    .iter()
                    .map(|(name, _)| name.clone()),
            );
            if !parsed.complete
                || parsed.command_index.is_none()
                || !parsed.split_expansions.is_empty()
            {
                return (names, tokens.len(), wrappers);
            }
            index += parsed.command_index.unwrap() + 1;
            continue;
        }
        if executable.as_deref() == Some("sudo") {
            wrappers.push("sudo".to_owned());
            index = after_sudo_options(tokens, index + 1);
            continue;
        }
        break;
    }
    (names, index, wrappers)
}

/// `_after_sudo_options` (:136-152).
pub fn after_sudo_options(tokens: &[String], mut index: usize) -> usize {
    while index < tokens.len() {
        let token = &tokens[index];
        if token == "--" {
            return index + 1;
        }
        let option_name = token.split('=').next().unwrap_or("");
        if SUDO_OPTIONS_WITH_VALUES.contains(&option_name)
            || SUDO_LONG_OPTIONS_WITH_VALUES.contains(&option_name)
        {
            index += if token.contains('=') { 1 } else { 2 };
            continue;
        }
        if token.starts_with('-') {
            index += 1;
            continue;
        }
        if env_assignment_name(token).is_some() {
            return index;
        }
        return index;
    }
    index
}
