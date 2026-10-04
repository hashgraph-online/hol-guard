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

/// `_windows_shell_tokens` (:36-92). Quoted POSIX escapes preserved; unquoted
/// path separators kept literal.
#[allow(dead_code)]
fn windows_shell_tokens(command: &str) -> Vec<String> {
    let mut tokens: Vec<String> = Vec::new();
    let mut token: Vec<char> = Vec::new();
    let mut started = false;
    let mut quote = '\0';
    let mut escaped = false;
    for current in command.chars() {
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
            token.push('\\');
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
        return command.split_whitespace().map(str::to_owned).collect();
    }
    if started {
        tokens.push(token.iter().collect());
    }
    tokens
}

/// `shell_tokens` (:95-103) → `(tokens, exact)`.
pub fn shell_tokens(command: &str) -> (Vec<String>, bool) {
    if cfg!(windows) {
        return (windows_shell_tokens(command), true);
    }
    match crate::shell_tokens(command, false) {
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
fn after_sudo_options(tokens: &[String], mut index: usize) -> usize {
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
