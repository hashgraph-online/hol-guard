//! Whether a prefix word is an environment setting at all, and whether the
//! text after its `=` is the text the program receives. A shell decides both,
//! and it decides them differently for a bare assignment prefix than for an
//! argument handed to `env`, so the two spellings read their values apart.

use crate::cloud_scrub_shell::ShellToken;

pub(super) fn assignment(token: &ShellToken) -> Option<(&str, &str)> {
    let (name, value) = token.value.split_once('=')?;
    let mut characters = name.chars();
    let first = characters.next()?;
    ((first == '_' || first.is_ascii_alphabetic())
        && characters.all(|value| value == '_' || value.is_ascii_alphanumeric()))
    .then_some((name, value))
}

/// A prefix word is an assignment only when its name and `=` are unquoted;
/// the shell runs `'LC_ALL=C' ls` as a program named `LC_ALL=C`.
pub(super) fn shell_assignment<'t>(
    chars: &[char],
    token: &'t ShellToken,
) -> Option<(&'t str, &'t str)> {
    let (name, value) = assignment(token)?;
    let raw = chars.get(token.start..token.end)?;
    (raw.len() > name.len()
        && raw[name.len()] == '='
        && raw[..name.len()].iter().copied().eq(name.chars()))
    .then_some((name, value))
}

/// The raw word has no expansion, substitution, glob or escape.
pub(super) fn literal_word(chars: &[char], token: &ShellToken) -> bool {
    literal_chars(&chars[token.start..token.end])
}

/// [`literal_word`] for an assignment, reading its value the way a shell does.
/// A shell applies tilde, parameter, command and arithmetic expansion and
/// quote removal to an assignment's value, but never field splitting or
/// pathname expansion, so `DEBUG=app:*` hands the program the four characters
/// `app:*`. Reading them as a glob refused to project a setting that changes
/// nothing about which program runs, and an unprojected prefix stops the
/// command extensions from evaluating at all. The name and its `=` are still
/// read as any other word; only the value carries the wider set.
pub(super) fn literal_assignment_word(chars: &[char], token: &ShellToken, name: &str) -> bool {
    let raw = &chars[token.start..token.end];
    let split = name.len() + 1;
    if raw.len() < split
        || raw[split - 1] != '='
        || !raw[..name.len()].iter().copied().eq(name.chars())
    {
        return literal_word(chars, token);
    }
    literal_chars(&raw[..split]) && raw[split..].iter().copied().all(literal_value_character)
}

/// [`literal_assignment_word`] for an `env` argument. A shell reads that word
/// as an ordinary argument, not as an assignment prefix, so brace expansion
/// and pathname expansion do reach it: `env A={x,y} prog` hands `env` two
/// settings. A pattern character counts as its own text only while one pair of
/// quotes covers the whole value; otherwise the word is read as any other.
pub(super) fn quoted_assignment_word(chars: &[char], token: &ShellToken, name: &str) -> bool {
    let raw = &chars[token.start..token.end];
    let split = name.len() + 1;
    let quoted = raw.len() > split + 1
        && matches!(raw[split], '\'' | '"')
        && raw[raw.len() - 1] == raw[split]
        && !raw[split + 1..raw.len() - 1].contains(&raw[split]);
    if quoted {
        literal_assignment_word(chars, token, name)
    } else {
        literal_word(chars, token)
    }
}

/// A character a shell leaves alone inside an assignment's value. `(` and `)`
/// stay out because they open an array assignment rather than a scalar, and
/// `~` and `!` stay out because the shell does expand those.
fn literal_value_character(character: char) -> bool {
    matches!(character, '*' | '?' | '[' | ']' | '{' | '}') || literal_chars(&[character])
}

/// The raw word's only expansions are `$TMPDIR`, `${TMPDIR}` or
/// `${TMPDIR:-/tmp}` and nothing in the command rebinds `TMPDIR`. Only a
/// reviewed projection drops such a setting: the projection never settles
/// below review, and moving it to the workspace sandbox, which sets `TMPDIR`
/// itself, re-checks the raw command.
pub(super) fn private_temp_word(chars: &[char], token: &ShellToken) -> bool {
    let word: String = chars[token.start..token.end].iter().collect();
    let command: String = chars.iter().collect();
    if !crate::pretool::workspace_contained::private_temp_expansions_only(&word)
        || crate::pretool::workspace_contained::rebinds_private_temp(&command)
    {
        return false;
    }
    let fallback = format!(
        "${}",
        crate::pretool::workspace_contained::PRIVATE_TEMP_WITH_FALLBACK
    );
    let rest: Vec<char> = word
        .replace(&fallback, "")
        .replace("${TMPDIR}", "")
        .replace("$TMPDIR", "")
        .chars()
        .collect();
    literal_chars(&rest)
}

fn literal_chars(word: &[char]) -> bool {
    !word.iter().any(|character| {
        matches!(
            character,
            '$' | '`'
                | '\\'
                | '('
                | ')'
                | '{'
                | '}'
                | '*'
                | '?'
                | '['
                | ']'
                | '~'
                | '<'
                | '>'
                | '!'
        )
    })
}
