//! `ln -s "$(pwd)/node_modules" ../wt/node_modules` names the working
//! directory through an expansion, so the whole command stayed opaque. Until
//! something in the list can change the directory, `$(pwd)`, `` `pwd` ``,
//! `$PWD` and `${PWD}` all expand to the session's verified working
//! directory. Writing that path in their place lets each step be judged on
//! the path it really names. Anything this pass does not fully understand
//! returns `None`, so the expansion stays opaque.

use super::lex::{items, names_variable, tokenize};
use super::{assignment, listed, KEYWORDS, MAX_COMMAND_CHARS, PRECOMMANDS, STATE_COMMANDS};

const MAX_DIRECTORY_CHARS: usize = 1024;

/// Builtins that change the shell's directory or its idea of it.
const DIRECTORY_COMMANDS: &str = "cd chdir dirs popd pushd";

/// The command with each working-directory expansion replaced by `cwd`;
/// `None` when nothing is replaced, the directory is not a plain absolute
/// literal, or any step at or before a replaced use could change the directory.
pub(super) fn project(command: &str, cwd: &str) -> Option<String> {
    if !literal_directory(cwd)
        || !command.is_ascii()
        || command.len() > MAX_COMMAND_CHARS
        || command.bytes().any(|b| b.is_ascii_control() && b != b'\t')
        // A changed `IFS` splits an unquoted use where the literal is whole,
        // and any other mention of `PWD` might set it.
        || names_variable(command, |name| name == "IFS" || name == "PWD")
    {
        return None;
    }
    let chars: Vec<char> = command.chars().collect();
    let (projected, last_use) = replace_uses(&chars, cwd)?;
    let projected_chars: Vec<char> = projected.chars().collect();
    let tokens = tokenize(&projected_chars)?;
    let list = items(&tokens)?;
    // Every replacement ends no later than `last_use` in the projection, so
    // each step that starts before it runs before or alongside a use.
    for (stages, _) in &list {
        let first = stages.first()?.first()?.0;
        if first >= last_use {
            break;
        }
        for stage in stages {
            let leading = stage
                .iter()
                .take_while(|&&(from, to)| assignment(&projected_chars[from..to]).is_some())
                .count();
            // The lexer keeps redirections as words, so one before the
            // command word (`2>/dev/null cd /etc`) would hide that word.
            if stage[..stage.len().min(leading + 1)]
                .iter()
                .any(|&(from, to)| {
                    projected_chars[from..to]
                        .iter()
                        .any(|c| matches!(c, '<' | '>'))
                })
            {
                return None;
            }
            let Some(&(from, to)) = stage.get(leading) else {
                continue;
            };
            let word: String = projected_chars[from..to]
                .iter()
                .filter(|&&c| !matches!(c, '\'' | '"' | '\\'))
                .collect();
            if word.contains('$')
                || listed(DIRECTORY_COMMANDS, &word)
                || listed(STATE_COMMANDS, &word)
                || listed(KEYWORDS, &word)
                || listed(PRECOMMANDS, &word)
                // zsh's AUTO_CD runs a bare directory name as `cd`.
                || std::path::Path::new(cwd).join(&word).is_dir()
            {
                return None;
            }
        }
    }
    Some(projected)
}

/// An absolute path whose characters the shell never splits, globs, quotes
/// or expands, and which still names a directory.
fn literal_directory(cwd: &str) -> bool {
    cwd.starts_with('/')
        && cwd.len() <= MAX_DIRECTORY_CHARS
        && !cwd.split('/').any(|part| part == "..")
        && cwd.chars().all(|c| {
            c.is_ascii_alphanumeric()
                || matches!(c, '_' | '.' | '/' | '@' | '%' | '+' | ':' | ',' | '-')
        })
        && std::fs::canonicalize(cwd).is_ok_and(|path| path.is_dir())
}

/// The text with every use outside single quotes and escapes replaced, and
/// the index in that text just after the last replacement.
fn replace_uses(chars: &[char], cwd: &str) -> Option<(String, usize)> {
    let mut out = String::with_capacity(chars.len() + cwd.len());
    let mut last_use = None;
    let mut single = false;
    let mut double = false;
    let mut index = 0usize;
    while index < chars.len() {
        let c = chars[index];
        if single {
            single = c != '\'';
            out.push(c);
            index += 1;
            continue;
        }
        let width = match c {
            '\'' if !double => {
                single = true;
                0
            }
            '"' => {
                double = !double;
                0
            }
            '\\' => {
                out.extend(chars.get(index..index + 2).unwrap_or(&chars[index..]));
                index += 2;
                continue;
            }
            '$' | '`' => use_width(&chars[index..])?,
            _ => 0,
        };
        if width == 0 {
            out.push(c);
            index += 1;
            continue;
        }
        out.push_str(cwd);
        // Byte and character offsets agree: the text is ASCII.
        last_use = Some(out.len());
        index += width;
    }
    Some((out, last_use?))
}

/// The length of a working-directory use at the start of `rest`, 0 when it
/// starts some other expansion, and `None` for a `$PWD` the shell would
/// subscript or modify (zsh's `$PWD[1]`, `$PWD:h`).
fn use_width(rest: &[char]) -> Option<usize> {
    let starts = |text: &str| {
        rest.len() >= text.len() && rest.iter().zip(text.chars()).all(|(a, b)| *a == b)
    };
    if starts("$(pwd)") || starts("${PWD}") {
        return Some(6);
    }
    if starts("`pwd`") {
        return Some(5);
    }
    if starts("$PWD") {
        return match rest.get(4) {
            Some(c) if c.is_ascii_alphanumeric() || *c == '_' => Some(0),
            Some('[' | ':') => None,
            _ => Some(4),
        };
    }
    Some(0)
}

#[cfg(test)]
#[path = "chain_literals_pwd_tests.rs"]
mod tests;
