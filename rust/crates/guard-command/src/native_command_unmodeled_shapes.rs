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

/// `which` options that only change how the lookup prints its answer. None of
/// them runs the program being looked up.
const LOOKUP_OPTIONS: &[&str] = &[
    "-a",
    "-s",
    "--all",
    "--read-alias",
    "--read-functions",
    "--show-dot",
    "--show-tilde",
    "--silent",
    "--skip-alias",
    "--skip-dot",
    "--skip-functions",
    "--skip-tilde",
    "--tty-only",
];

/// How many bytes of `text` the leading plain word covers. The name charset is
/// the one a lookup operand may use; anything else ends the word.
fn lookup_word_end(text: &str) -> usize {
    text.char_indices()
        .take_while(|(_, letter)| {
            letter.is_ascii_alphanumeric() || matches!(letter, '.' | '_' | '+' | '-')
        })
        .map(|(at, letter)| at + letter.len_utf8())
        .last()
        .unwrap_or(0)
}

/// Whether `letter` ends a lookup operand the way the shell does. A quote
/// does not: the shell glues `foo'bar'` into one word, so the plain prefix is
/// not an operand of its own and the run stops before it.
fn ends_lookup_word(letter: char) -> bool {
    letter.is_whitespace() || matches!(letter, ';' | '&' | '|' | ')' | '}' | '`')
}

/// The names a lookup prints paths for, and how far its operands reach.
///
/// `which` takes a list, so `which doctl kubectl` looks up both and runs
/// neither; reading only the first left the rest of the line looking like a
/// program. Options come before the names, as `which` reads them. A word that
/// is neither a known option nor a plain name leaves the whole lookup alone.
fn lookup_run(text: &str, options_allowed: bool) -> Option<(Vec<&str>, usize)> {
    let mut names: Vec<&str> = Vec::new();
    let mut reading_options = options_allowed;
    let mut cursor = 0;
    let mut end = 0;
    loop {
        let rest = &text[cursor..];
        let length = lookup_word_end(rest);
        if length == 0 || length > 64 {
            break;
        }
        let word = &rest[..length];
        // A word the shell does not end here, and an option this list does
        // not know, end the run: what follows is not proven to be an operand.
        if !rest[length..].chars().next().is_none_or(ends_lookup_word) {
            break;
        }
        if word.starts_with('-') {
            if !(reading_options && LOOKUP_OPTIONS.contains(&word)) {
                break;
            }
        } else {
            reading_options = false;
            names.push(word);
        }
        cursor += length;
        end = cursor;
        let blanks = rest[length..].len() - rest[length..].trim_start_matches([' ', '\t']).len();
        if blanks == 0 {
            break;
        }
        cursor += blanks;
    }
    (!names.is_empty()).then_some((names, end))
}

/// How far a run of plain redirections reaches, when it ends at the close of a
/// command substitution, and whether that run discards what the lookup prints.
///
/// Only redirections the shell cannot write a file of the user's with count:
/// `/dev/null` and a duplicated descriptor. The stripped text is what the rest
/// of this scan reviews, so a target naming a path has to keep its
/// substitution opaque — `$(command -v doctl > .git/hooks/post-checkout)`
/// truncates that hook, and reading it as `doctl` would hide the write.
/// `&& rm -rf ~)` is not a redirection either, so it reads as no run at all
/// and the substitution keeps its `true`. The answer is the offset of the `)`
/// within `text`.
fn redirections_end(text: &str) -> Option<(usize, bool)> {
    let bytes = text.as_bytes();
    let mut at = 0;
    let mut seen = false;
    let mut discards_stdout = false;
    loop {
        while matches!(bytes.get(at), Some(b' ') | Some(b'\t')) {
            at += 1;
        }
        match bytes.get(at) {
            Some(b')') => return seen.then_some((at, discards_stdout)),
            None => return None,
            _ => {}
        }
        let descriptor = at;
        while bytes.get(at).is_some_and(u8::is_ascii_digit) {
            at += 1;
        }
        let numbered = &text[descriptor..at];
        // `&>` sends both streams, so it carries stdout whatever precedes it.
        let both_streams = matches!(bytes.get(at), Some(b'&'));
        if both_streams {
            at += 1;
        }
        if !matches!(bytes.get(at), Some(b'>') | Some(b'<')) {
            return None;
        }
        let writes = bytes[at] == b'>';
        at += 1;
        // `>>` appends and `>&` duplicates; both still only redirect.
        let duplicating = matches!(bytes.get(at), Some(b'&'));
        if matches!(bytes.get(at), Some(b'>') | Some(b'&')) {
            at += 1;
        }
        while matches!(bytes.get(at), Some(b' ') | Some(b'\t')) {
            at += 1;
        }
        let target = at;
        while bytes.get(at).is_some_and(|letter| {
            letter.is_ascii_alphanumeric() || matches!(*letter, b'/' | b'.' | b'_' | b'-')
        }) {
            at += 1;
        }
        let word = &text[target..at];
        let duplicates =
            duplicating && !word.is_empty() && word.bytes().all(|letter| letter.is_ascii_digit());
        if !(word == "/dev/null" || duplicates) {
            return None;
        }
        discards_stdout |=
            writes && word == "/dev/null" && (both_streams || matches!(numbered, "" | "1"));
        seen = true;
    }
}

fn strip_one_lookup(text: &str) -> Option<String> {
    for (lead, options_allowed) in [
        ("command -v ", false),
        ("command -V ", false),
        ("which ", true),
    ] {
        for (at, _) in text.match_indices(lead) {
            let before = text[..at].trim_end_matches([' ', '\t']);
            if !(before.is_empty() || before.ends_with([';', '&', '|', '(', '{', '\n', '`'])) {
                continue;
            }
            let name_start = at + lead.len();
            let Some((names, length)) = lookup_run(&text[name_start..], options_allowed) else {
                continue;
            };
            let end = name_start + length;
            let rest = &text[end..];
            // A lookup that fills the whole substitution leaves a plain word
            // naming what it looked up; anything else keeps a `true` that runs
            // nothing. A trailing run of redirections still leaves the lookup
            // alone in the substitution, and `$(command -v cygpath &>/dev/null)`
            // is how a generated activation script asks whether a program
            // exists, so the redirections are read past to find the close.
            let closing = if !before.ends_with("$(") {
                None
            } else if rest.starts_with(')') {
                Some((end + 1, false))
            } else {
                redirections_end(rest).map(|(offset, discarded)| (end + offset + 1, discarded))
            };
            // A run that discards the lookup's stdout leaves the substitution
            // printing nothing, so the surrounding command never sees the name
            // the lookup found; only its exit status survives. Standing the
            // whole substitution down to `true` says that, where expanding it
            // to the name would read as a program the shell went on to run.
            let filler = match closing {
                Some((_, false)) => names.join(" "),
                _ => "true".to_owned(),
            };
            let (from, to) = match closing {
                Some((close, _)) => (before.len() - 2, close),
                None => (at, end),
            };
            return Some(format!("{}{}{}", &text[..from], filler, &text[to..]));
        }
    }
    None
}
