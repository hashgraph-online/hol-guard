//! Quoted text a helper's `echo` prints.
//!
//! A credential helper often answers Git from a shell function:
//! `!f() { echo "username=x"; echo "password=$(gh auth token)"; }; f`. A
//! quoted argument of `echo` is data Git reads back from the helper's output,
//! not a path a shell resolves, so it may hold spaces. A command substitution
//! in it does run a program, so its words move out to a command of their own
//! and are screened like any other helper word.
//!
//! The text stays data only while nothing can hand it back to a shell, so a
//! value with a pipe, a redirect, a line break, an alias, a function named
//! `echo`, a `$_` that re-reads the last argument or an unquoted `$(...)` that
//! runs what `echo` prints is left as written and keeps its review. So is a
//! command whose name is only partly `echo`, as in `echo'X'`.

/// `value` with each quoted `echo` argument replaced by one plain word,
/// followed by the commands its substitutions run. A span this reader cannot
/// prove is data is left as written.
pub(super) fn mask_echoed_text(value: &str) -> String {
    let compact: String = value.chars().filter(|c| !c.is_whitespace()).collect();
    if value.contains(['|', '<', '>', '\n', '\r'])
        || compact.contains("$_")
        || compact.contains("${_")
        || compact.contains("echo(")
        || value
            .split(|c: char| c.is_whitespace() || "!;&(){}".contains(c))
            .any(|word| matches!(word, "alias" | "function"))
    {
        return value.to_owned();
    }
    let chars: Vec<char> = value.chars().collect();
    let mut out = String::with_capacity(value.len());
    let mut moved = Vec::new();
    // The unquoted text of the current command's first word, and how many
    // words that command has started.
    let mut first = String::new();
    let mut words = 0usize;
    let mut in_word = false;
    let mut index = usize::from(chars.first() == Some(&'!'));
    out.extend(&chars[..index]);
    while index < chars.len() {
        let c = chars[index];
        if c.is_whitespace() {
            in_word = false;
        } else if c == '(' && index > 0 && chars[index - 1] == '$' {
            // An unquoted substitution runs what its commands print.
            return value.to_owned();
        } else if ";&(){}".contains(c) {
            in_word = false;
            words = 0;
            first.clear();
        } else {
            if !in_word {
                in_word = true;
                words += 1;
            }
            if c == '"' || c == '\'' {
                if let Some(length) = chars[index + 1..].iter().position(|&q| q == c) {
                    let close = index + 1 + length;
                    let inner: String = chars[index + 1..close].iter().collect();
                    let commands = (words > 1 && first == "echo")
                        .then(|| substitutions(&inner, c == '"'))
                        .flatten();
                    match commands {
                        Some(commands) => {
                            out.push('x');
                            moved.extend(commands);
                        }
                        None => out.extend(&chars[index..=close]),
                    }
                    if words == 1 {
                        // A quote in the command name makes it some other
                        // command, such as a function `echoX`.
                        first.push(c);
                    }
                    index = close + 1;
                    continue;
                }
            } else if words == 1 {
                first.push(c);
            }
        }
        out.push(c);
        index += 1;
    }
    for command in moved {
        out.push_str("; ");
        out.push_str(&command);
    }
    out
}

/// The commands the substitutions in a quoted span run. A single-quoted span
/// expands nothing. `None` for a double-quoted span with any expansion other
/// than a plain `$(...)` holding no quote, expansion or separator.
fn substitutions(inner: &str, double: bool) -> Option<Vec<String>> {
    if !double {
        return Some(Vec::new());
    }
    if inner.contains(['`', '\\']) {
        return None;
    }
    let mut commands = Vec::new();
    let mut rest = inner;
    while let Some(at) = rest.find('$') {
        let body = rest[at + 1..].strip_prefix('(')?;
        let end = body.find(')')?;
        let command = &body[..end];
        if command.trim().is_empty() || command.contains(['$', '(', '"', '\'', ';', '&', '{', '}'])
        {
            return None;
        }
        commands.push(command.to_owned());
        rest = &body[end + 1..];
    }
    Some(commands)
}
