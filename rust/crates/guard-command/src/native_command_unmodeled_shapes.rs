//! Shell shapes the unmodeled-command check can read without a program
//! owner: heredocs that only feed data, plain `awk` filters and lookups that
//! print where a program is without running it.

use super::SHELL_PREFIXES;

/// Interpreters whose standard-input program is a heredoc this module reads.
const HEREDOC_PYTHON: &[&str] = &["python", "python3", "python -", "python3 -"];

/// Text a Python program needs to reach the operating system, load code it
/// computes, or inspect its own objects. A program with none of it and no
/// `import` statement has only the builtins, which cannot start a program.
const PYTHON_UNBOUNDED: &[&str] = &[
    "__",
    "getattr",
    "setattr",
    "delattr",
    "globals",
    "locals",
    "vars",
    "dir(",
    "eval",
    "exec",
    "compile",
    "breakpoint",
    "help",
    "license",
    "credits",
    "copyright",
    "input",
    "memoryview",
    "type(",
];

/// Whether `command`, the whole simple command a heredoc feeds, is Python
/// reading its program from standard input named as `-`.
pub(crate) fn python_stdin(command: &str) -> bool {
    command.ends_with(" -") && HEREDOC_PYTHON.contains(&command)
}

/// Whether a Python program reads only builtins, so it cannot start another
/// program. An `import` keyword starts a statement, so one inside a string
/// literal (preceded by a quote or a word) is data. So is one followed by
/// `.`, such as JavaScript's `import.meta`, which no Python statement allows.
pub(crate) fn python_is_builtin_only(body: &[&str]) -> bool {
    // A coding declaration can re-decode the whole source into other text.
    if body
        .iter()
        .any(|row| row.to_ascii_lowercase().contains("coding"))
    {
        return false;
    }
    body.iter().all(|row| {
        if !row.is_ascii() {
            return false;
        }
        let lowered = row.to_ascii_lowercase();
        if PYTHON_UNBOUNDED.iter().any(|word| lowered.contains(word)) {
            return false;
        }
        !lowered.match_indices("import").any(|(at, _)| {
            !lowered[at + "import".len()..].starts_with('.')
                && lowered[..at]
                    .chars()
                    .next_back()
                    .is_none_or(|before| before.is_whitespace() || matches!(before, ';' | ':'))
        })
    })
}

/// Every heredoc in the text feeds data, and the text without them. A heredoc
/// is data when its delimiter is quoted or its body expands nothing and it is
/// closed. A `python` or `python3` that reads its program from one whose body
/// uses only builtins is replaced by `true`, since it can own nothing.
/// `None` for a heredoc that feeds anything but `cat` or such a program.
/// The flag says whether text had any.
pub(super) fn data_heredocs(text: &str) -> Option<(String, bool)> {
    if !text.contains("<<") {
        return Some((text.to_owned(), false));
    }
    let mut out: Vec<String> = Vec::new();
    let mut lines = text.lines();
    while let Some(line) = lines.next() {
        let Some((before, after)) = line.split_once("<<") else {
            out.push(line.to_owned());
            continue;
        };
        if after.starts_with('<') || before.contains(['\'', '"']) {
            return None;
        }
        let strip_tabs = after.starts_with('-');
        let after = after.strip_prefix('-').unwrap_or(after).trim_start();
        let quoted = after.starts_with(['\'', '"']);
        let end = after[usize::from(quoted)..]
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .map_or(after.len(), |at| at + usize::from(quoted));
        let delimiter = after[..end].trim_matches(['\'', '"']);
        let mut rest = &after[end..];
        if quoted {
            rest = rest.strip_prefix(['\'', '"'])?;
        }
        if delimiter.is_empty() || rest.contains("<<") {
            return None;
        }
        let mut body = Vec::new();
        loop {
            let next = lines.next()?;
            // The shell closes a heredoc only on the delimiter alone, after
            // leading tabs for `<<-`.
            let candidate = if strip_tabs {
                next.trim_start_matches('\t')
            } else {
                next
            };
            if candidate == delimiter {
                break;
            }
            body.push(next);
        }
        if !quoted && body.iter().any(|row| row.contains(['$', '`', '\\'])) {
            return None;
        }
        let split = before.rfind([';', '&', '|', '(']).map_or(0, |at| at + 1);
        let (lead, command) = before.split_at(split);
        let command = command.trim();
        let inert = HEREDOC_PYTHON.contains(&command) && python_is_builtin_only(&body);
        // Any other program may do more than read its input.
        if !inert && command.split_whitespace().next() != Some("cat") {
            return None;
        }
        let command = if inert { "true" } else { command };
        out.push(format!("{lead}{command}{rest}"));
    }
    Some((out.join("\n"), true))
}

/// One shell word or operator run, quoting kept, or `None` when a quote is
/// left open.
fn shell_pieces(text: &str) -> Option<Vec<(String, bool)>> {
    let mut pieces: Vec<(String, bool)> = Vec::new();
    let (mut word, mut operator) = (String::new(), String::new());
    let (mut quote, mut escaped) = (None, false);
    for character in text.chars() {
        if let Some(open) = quote {
            word.push(character);
            if character == open {
                quote = None;
            }
            continue;
        }
        if escaped {
            escaped = false;
            word.push(character);
            continue;
        }
        let is_operator = matches!(character, ';' | '&' | '|' | '<' | '>' | '(' | ')' | '\n');
        if !is_operator && !operator.is_empty() {
            pieces.push((std::mem::take(&mut operator), true));
        }
        if is_operator || character.is_whitespace() {
            if !word.is_empty() {
                pieces.push((std::mem::take(&mut word), false));
            }
            if is_operator {
                operator.push(character);
            }
            continue;
        }
        match character {
            '\'' | '"' => quote = Some(character),
            '\\' => escaped = true,
            _ => {}
        }
        word.push(character);
    }
    if quote.is_some() || escaped {
        return None;
    }
    if !word.is_empty() {
        pieces.push((word, false));
    }
    if !operator.is_empty() {
        pieces.push((operator, true));
    }
    Some(pieces)
}

/// An `awk` whose program only filters and prints cannot start a program:
/// it names no `system`, `getline`, pipe or command substitution, loads no
/// program file or extension, and takes only `-F` and `-v` options. Such a
/// command becomes `true`, so the interpreter check ignores it.
pub(super) fn without_plain_awk(shell: &str) -> String {
    let Some(pieces) = shell_pieces(shell) else {
        return shell.to_owned();
    };
    let mut out: Vec<String> = Vec::new();
    let mut at_command = true;
    let mut index = 0;
    while index < pieces.len() {
        let (piece, is_operator) = &pieces[index];
        if *is_operator {
            if !piece.contains(['<', '>']) {
                at_command = true;
            }
            out.push(piece.clone());
            index += 1;
            continue;
        }
        if !at_command {
            out.push(piece.clone());
            index += 1;
            continue;
        }
        if SHELL_PREFIXES.contains(&piece.as_str()) {
            out.push(piece.clone());
            index += 1;
            continue;
        }
        at_command = false;
        let base = piece.rsplit('/').next().unwrap_or_default();
        if !matches!(base, "awk" | "gawk" | "mawk" | "nawk") {
            out.push(piece.clone());
            index += 1;
            continue;
        }
        // A redirect may come before the program, so the arguments run to the
        // next command separator.
        let end = pieces[index..]
            .iter()
            .position(|(text, operator)| {
                *operator
                    && text
                        .replace(">&", ">")
                        .replace("<&", "<")
                        .replace("&>", ">")
                        .contains([';', '|', '&', '(', ')', '\n'])
            })
            .map_or(pieces.len(), |at| index + at);
        let plain = pieces[index + 1..end].iter().all(|(word, operator)| {
            if *operator {
                return true;
            }
            let flagged = word.starts_with('-');
            if flagged {
                return word.starts_with("-F") || word.starts_with("-v");
            }
            let lowered = word.to_ascii_lowercase();
            !["system", "getline", "popen", "|", "`", "$(", "@", "${"]
                .iter()
                .any(|bad| lowered.contains(bad))
        });
        if plain {
            out.push("true".to_owned());
        } else {
            out.extend(pieces[index..end].iter().map(|(word, _)| word.clone()));
        }
        index = end;
    }
    out.join(" ")
}

/// The text with each `command -v NAME` and `which NAME` lookup, in command
/// position or as a whole substitution, replaced by a plain word that keeps the
/// looked-up name visible, since a substitution in command position runs it.
pub(super) fn without_lookups(text: &str) -> String {
    let mut current = text.to_owned();
    for _ in 0..16 {
        match strip_one_lookup(&current) {
            Some(next) => current = next,
            None => break,
        }
    }
    current
}

fn strip_one_lookup(text: &str) -> Option<String> {
    for lead in ["command -v ", "command -V ", "which "] {
        for (at, _) in text.match_indices(lead) {
            let before = text[..at].trim_end_matches([' ', '\t']);
            if !(before.is_empty() || before.ends_with([';', '&', '|', '(', '{', '\n', '`'])) {
                continue;
            }
            let name_start = at + lead.len();
            let name: String = text[name_start..]
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '+' | '-'))
                .collect();
            if name.is_empty() || name.starts_with('-') || name.len() > 64 {
                continue;
            }
            let end = name_start + name.len();
            let after = text[end..].chars().next();
            if !after.is_none_or(|c| {
                c.is_whitespace() || matches!(c, ';' | '&' | '|' | ')' | '"' | '\'' | '}' | '`')
            }) {
                continue;
            }
            let whole = before.ends_with("$(") && after == Some(')');
            let (from, to, filler) = if whole {
                (before.len() - 2, end + 1, name.as_str())
            } else {
                (at, end, "true")
            };
            return Some(format!("{}{}{}", &text[..from], filler, &text[to..]));
        }
    }
    None
}
