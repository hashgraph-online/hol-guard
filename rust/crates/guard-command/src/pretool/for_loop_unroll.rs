//! A shell `for` loop over literal words is the same command list written out
//! once per word. Expanding it lets the ordinary proofs decide each unrolled
//! step, so a read-only loop is admitted exactly when its unrolled form is and
//! nothing about the loop itself grants extra authority. Anything this
//! recognizer does not fully understand returns `None`, which keeps the
//! existing review behavior.

#[path = "for_loop_unroll_body.rs"]
pub(super) mod body;

use body::{
    body_items, rebinds, redirect_tail, references_are_quoted, references_stand_alone, substitute,
    unquote_whole_references,
};

const MAX_WORDS: usize = 32;
const MAX_WORD_BYTES: usize = 256;
const MAX_BODY_BYTES: usize = 2048;
const MAX_UNROLLED_BYTES: usize = 8192;

const CONTROL_WORDS: &[&str] = &[
    "!", "[[", "case", "coproc", "do", "done", "elif", "else", "esac", "fi", "for", "function",
    "if", "in", "select", "then", "time", "until", "while",
];

/// zsh specials outside the PATH family that `valid_identifier` rejects.
const SHELL_SPECIAL_NAMES: &[&str] = &[
    "argv",
    "fignore",
    "histchars",
    "mailpath",
    "pipestatus",
    "psvar",
    "signals",
    "status",
    "watch",
];

/// The unrolled command text for a top-level `for NAME in WORD...; do BODY; done`
/// over literal words and glob patterns, or `None` when the command is
/// anything else.
pub(super) fn unroll(command: &str) -> Option<String> {
    if command
        .chars()
        .any(|c| c.is_control() && !matches!(c, '\n' | '\t'))
    {
        return None;
    }
    let (prefix, rest) = cd_prefix(command.trim())?;
    let rest = keyword(rest, "for")?;
    let (name, rest) = next_word(rest)?;
    if !valid_identifier(name) || !ordinary_loop_name(name) {
        return None;
    }
    let rest = keyword(rest, "in")?;
    let (words, rest) = header_words(rest)?;
    if words.is_empty() || words.len() > MAX_WORDS {
        return None;
    }
    let rest = rest.trim_start_matches([' ', '\t', '\n', ';']);
    let rest = keyword(rest, "do")?;
    let (items, _, tail) = body_items(rest, name, &["done"])?;
    let tail = redirect_tail(tail)?;
    if items.is_empty() || items.iter().any(|(text, _)| rebinds(text, name)) {
        return None;
    }
    // A glob reaches the body as the names the shell expanded it to, one
    // argument each, while the unrolled text hands the body the pattern. The
    // two are the same work only while the body reads the loop variable as a
    // whole word of its own, and only while the pattern reaches the unrolled
    // text bare, which is why a reference the body quotes on its own loses its
    // quotes first.
    // Taking those quotes off is only faithful while every word is a single
    // field, so a header that mixes a pattern with a word holding separators
    // has no written form that is both and keeps its review.
    let patterned = words.iter().any(|word| word.contains(['*', '?', '[']));
    let spaced = words.iter().any(|word| word.contains([' ', '\t']));
    if patterned && spaced {
        return None;
    }
    let items = if patterned {
        let items: Vec<(String, &'static str)> = items
            .into_iter()
            .map(|(text, separator)| (unquote_whole_references(&text), separator))
            .collect();
        if !items.iter().all(|(text, _)| references_stand_alone(text)) {
            return None;
        }
        items
    } else {
        if spaced && !items.iter().all(|(text, _)| references_are_quoted(text)) {
            return None;
        }
        items
    };
    let mut out = prefix;
    for word in &words {
        for (text, separator) in &items {
            let step = substitute(text, word)?;
            out.push_str(&step);
            if !tail.is_empty() {
                out.push(' ');
                out.push_str(&tail);
            }
            out.push_str(separator);
        }
        if out.len() > MAX_UNROLLED_BYTES {
            return None;
        }
    }
    let trimmed = out.trim_end_matches([' ', ';']);
    Some(trimmed.to_owned())
}

/// An optional leading `cd DIR && ` with a literal directory. It is kept once
/// in front of the unrolled list. If `cd` fails the loop never runs, while the
/// unrolled list may still run its later items; the unrolled form can only do
/// more, so admitting it still covers the loop.
fn cd_prefix(command: &str) -> Option<(String, &str)> {
    let Some(rest) = keyword(command, "cd") else {
        return Some((String::new(), command));
    };
    let (dir, rest) = next_word(rest)?;
    if !safe_value(dir) || dir.starts_with('-') {
        return None;
    }
    let rest = rest.trim_start_matches([' ', '\t']).strip_prefix("&&")?;
    Some((
        format!("cd {dir} && "),
        rest.trim_start_matches([' ', '\t', '\n']),
    ))
}

/// Consume `keyword` followed by whitespace.
fn keyword<'a>(text: &'a str, keyword: &str) -> Option<&'a str> {
    let text = text.trim_start_matches([' ', '\t', '\n']);
    let rest = text.strip_prefix(keyword)?;
    rest.starts_with([' ', '\t', '\n'])
        .then(|| rest.trim_start_matches([' ', '\t']))
}

fn next_word(text: &str) -> Option<(&str, &str)> {
    let end = text.find([' ', '\t', '\n', ';'])?;
    (end > 0).then(|| (&text[..end], &text[end..]))
}

pub(super) fn valid_identifier(name: &str) -> bool {
    // Loop variables also modify the environment seen by commands in the
    // body. Rebinding PATH, HOME, IFS, Git configuration variables, or other
    // exported uppercase names can change which commands actually execute.
    // Only ordinary lowercase identifiers are admitted to this proof.
    // Exclude a leading underscore because '_' itself is shell-special.
    // zsh additionally ties these lowercase arrays to PATH, CDPATH, FPATH,
    // MANPATH and MODULE_PATH, so they can change command lookup.
    if matches!(
        name,
        "path" | "cdpath" | "fpath" | "manpath" | "module_path"
    ) {
        return false;
    }
    let mut chars = name.chars();
    chars.next().is_some_and(|first| first.is_ascii_lowercase())
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

fn safe_value(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_WORD_BYTES
        && value.chars().all(|c| {
            c.is_ascii_alphanumeric()
                || matches!(c, '_' | '.' | '/' | '@' | '%' | '+' | '=' | ':' | ',' | '-')
        })
}

/// A quoted word whose text holds the field separators the quotes protect,
/// such as `for spec in "1 first" "2 second"`.
///
/// The word is written back where the expansion stood, and the body keeps its
/// own quotes around that place, so a quoted reference becomes the quoted word
/// and stays the one field the loop passed it. Every field has to be a literal
/// word of its own, so the text written out can hold no operator, expansion or
/// pattern the loop never ran.
fn spaced_value(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_WORD_BYTES
        && value.contains([' ', '\t'])
        && value
            .split([' ', '\t'])
            .all(|field| field.is_empty() || safe_value(field))
}

/// A glob pattern the shell expands against the directory the loop runs in,
/// such as `*.ts`, `src/*.ts` or `packages/*/`.
///
/// Unrolling the loop over the pattern hands the body the same word the shell
/// expands there, so the ordinary proofs decide the matches exactly as they
/// decide them in the command the unrolled text spells out, and a pattern that
/// matches nothing is the word the shell passes on. That parity is the point:
/// `wc -l *.ts` and a loop that runs `wc -l` over `*.ts` are the same work, so
/// the loop must not keep a review the written-out command does not get.
///
/// A pattern that starts at the root or reaches above the working directory
/// names matches outside the directory the loop runs in, so it keeps its
/// review. So does one that opens with `-`, which the body's program reads as
/// an option when the pattern matches nothing and the shell passes the word
/// on, and one that opens with `[`, whose bracket expression is a character
/// set the text itself does not spell out.
///
/// A pattern without a directory in it only reads as a path when its own text
/// says so, by naming a directory or a file type. `for id in PRRT_example*`
/// walks identifiers the shell never expands, and the body then runs its
/// program over the pattern itself, so a bare word keeps its review however
/// the loop is written.
///
/// The body reads the loop variable unquoted, so each name the pattern matches
/// has to be a single field once the shell splits it. The proofs that expand
/// the pattern own that rule: `read_globs` admits a match only when its name
/// holds no whitespace, and refuses a match of a directoryless pattern that
/// begins with `-` or holds the `name=value` an operand would read as an
/// assignment rather than as a file. Those proofs read the pattern the body
/// is handed, so the body has to read the loop variable as a whole word of
/// its own; `references_stand_alone` holds it to that.
fn pattern_value(value: &str) -> bool {
    value.len() <= MAX_WORD_BYTES
        && value.contains(['*', '?', '['])
        && !value.starts_with(['/', '-', '['])
        // `..` reaches above the working directory, so the matches would sit
        // outside it.
        && !value.split('/').any(|segment| segment == "..")
        && (value.contains('/') || names_a_file_type(value))
        && value.chars().all(|c| {
            c.is_ascii_alphanumeric()
                || matches!(
                    c,
                    '_' | '.' | '/' | '@' | '%' | '+' | '=' | ':' | ',' | '-' | '*' | '?' | '['
                        | ']'
                )
        })
}

/// A pattern with no directory in it whose own text reads as a path: a
/// directory glob such as `*/`, or a name carrying a literal file type such
/// as `*.ts`.
///
/// The extension has to be spelled out, because the text is all the loop says
/// about what the pattern will match.
fn names_a_file_type(value: &str) -> bool {
    if let Some(stem) = value.strip_suffix('/') {
        return !stem.is_empty();
    }
    value.rsplit_once('.').is_some_and(|(stem, extension)| {
        !stem.is_empty() && !extension.is_empty() && !extension.contains(['*', '?', '[', ']'])
    })
}

/// Literal words, and glob patterns, up to the first unquoted `;` or newline.
///
/// A quoted word is the text itself rather than a pattern, so it keeps the
/// literal rule: writing it back out unquoted would otherwise hand the body a
/// pattern the loop never expanded. Its text may hold the separators the
/// quotes protect, which [`spaced_value`] admits.
fn header_words(text: &str) -> Option<(Vec<String>, &str)> {
    let mut words: Vec<(String, bool)> = Vec::new();
    let mut current = String::new();
    let mut in_word = false;
    let mut quoted = false;
    let mut chars = text.char_indices().peekable();
    while let Some((index, c)) = chars.next() {
        match c {
            ' ' | '\t' => {
                if in_word {
                    words.push((std::mem::take(&mut current), quoted));
                    in_word = false;
                    quoted = false;
                }
            }
            ';' | '\n' => {
                if in_word {
                    words.push((current, quoted));
                }
                return words
                    .iter()
                    .all(|(word, quoted)| {
                        safe_value(word)
                            || (*quoted && spaced_value(word))
                            || (!quoted && pattern_value(word))
                    })
                    .then(|| {
                        (
                            words.into_iter().map(|(word, _)| word).collect(),
                            &text[index..],
                        )
                    });
            }
            '\'' => {
                in_word = true;
                quoted = true;
                loop {
                    match chars.next()?.1 {
                        '\'' => break,
                        other => current.push(other),
                    }
                }
            }
            '"' => {
                in_word = true;
                quoted = true;
                loop {
                    match chars.next()?.1 {
                        '"' => break,
                        '$' | '`' | '\\' => return None,
                        other => current.push(other),
                    }
                }
            }
            '$' | '`' | '\\' | '(' | ')' | '{' | '}' | '~' | '&' | '|' | '<' | '>' | '#' | '!' => {
                return None
            }
            other => {
                in_word = true;
                current.push(other);
            }
        }
    }
    None
}

/// `valid_identifier` already limits loop variables to lowercase names. The
/// `*_proxy` names are lowercase environment variables, and the zsh specials
/// change shell state, so binding either changes what the body would run.
pub(super) fn ordinary_loop_name(name: &str) -> bool {
    !name.ends_with("_proxy") && !SHELL_SPECIAL_NAMES.contains(&name)
}
