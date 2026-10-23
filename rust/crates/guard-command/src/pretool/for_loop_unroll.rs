//! A shell `for` loop over literal words is the same command list written out
//! once per word. Expanding it lets the ordinary proofs decide each unrolled
//! step, so a read-only loop is admitted exactly when its unrolled form is and
//! nothing about the loop itself grants extra authority. Anything this
//! recognizer does not fully understand returns `None`, which keeps the
//! existing review behavior.

#[path = "for_loop_unroll_body.rs"]
pub(super) mod body;

use body::{body_items, rebinds, redirect_tail, substitute};

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

/// A glob pattern that names paths under a directory the pattern itself spells
/// out, such as `src/*.ts` or `packages/*/`.
///
/// Every name such a pattern matches begins with that directory, so unrolling
/// the loop over the pattern puts the same directory in front of the ordinary
/// path proofs as the names it expands into, and a pattern that matches
/// nothing is the word the shell passes on. A pattern with no directory in it
/// is a bare word that need not be a path at all — `for id in PRRT_example*`
/// walks identifiers the shell never expands — so it keeps its review. So does
/// a pattern that starts with a metacharacter: it can match a name beginning
/// with `-`, which the body's program reads as an option rather than as a path.
///
/// The body reads the loop variable unquoted, so each name the pattern matches
/// has to be a single field once the shell splits it. The proof that expands
/// the pattern owns that rule: `read_globs` admits a match only when its name
/// holds no whitespace.
fn pattern_value(value: &str) -> bool {
    value.len() <= MAX_WORD_BYTES
        && value.contains(['*', '?', '['])
        && value.contains('/')
        && value.starts_with(|c: char| c.is_ascii_alphanumeric() || matches!(c, '_' | '.'))
        // `..` reaches above that directory, so the matches would sit outside it.
        && !value.split('/').any(|segment| segment == "..")
        && value.chars().all(|c| {
            c.is_ascii_alphanumeric()
                || matches!(
                    c,
                    '_' | '.' | '/' | '@' | '%' | '+' | '=' | ':' | ',' | '-' | '*' | '?' | '['
                        | ']'
                )
        })
}

/// Literal words, and glob patterns, up to the first unquoted `;` or newline.
///
/// A quoted word is the text itself rather than a pattern, so it keeps the
/// literal rule: writing it back out unquoted would otherwise hand the body a
/// pattern the loop never expanded.
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
                    .all(|(word, quoted)| safe_value(word) || (!quoted && pattern_value(word)))
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
