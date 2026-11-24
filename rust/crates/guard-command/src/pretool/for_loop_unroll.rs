//! A shell `for` loop over literal words is the same command list written out
//! once per word. Expanding it lets the ordinary proofs decide each unrolled
//! step, so a read-only loop is admitted exactly when its unrolled form is and
//! nothing about the loop itself grants extra authority. Anything this
//! recognizer does not fully understand returns `None`, which keeps the
//! existing review behavior.

#[path = "for_loop_unroll_body.rs"]
pub(super) mod body;
#[path = "for_loop_unroll_conditional.rs"]
mod conditional;

use body::{
    body_items, rebinds, redirect_tail, references_are_quoted, references_stand_alone,
    unquote_whole_references,
};

const MAX_WORDS: usize = 32;
const MAX_WORD_BYTES: usize = 256;
const MAX_BODY_BYTES: usize = 2048;
const MAX_UNROLLED_BYTES: usize = crate::MAX_COMMAND_BYTES;

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
#[cfg(test)]
pub(super) fn unroll(command: &str) -> Option<String> {
    unroll_at(command, None)
}

/// [`unroll`], also reading a word spelled from the home directory.
///
/// The shell expands an unquoted `~/` at the start of a loop word before the
/// loop runs, so `for d in ~/work/a` hands the body the absolute path. The
/// unrolled text writes that path out, as the loop spelled with it is
/// written, so a quoted reference in the body still names the home path and
/// not a literal `./~`. Only a home made of plain path characters is written
/// out; any other keeps the review.
pub(super) fn unroll_at(command: &str, home_dir: Option<&str>) -> Option<String> {
    unrolled(command, home_dir, Place::Alone).map(|(text, _)| text)
}

/// Where a loop stands in the command it was read from.
#[derive(Clone, Copy, PartialEq)]
enum Place {
    /// The loop is the whole command, with at most a filter or redirect after
    /// `done`.
    Alone,
    /// The loop starts one item of a longer command list. `gated` says the
    /// item follows `&&` or `||`, so the loop may not run at all.
    InList { gated: bool },
}

/// A loop that opens the text, written out, and the text after its `done`,
/// which is empty or starts with a list separator.
///
/// A loop over literal words runs its body once per word, every time, so the
/// written-out list is the same work wherever the loop stands in a list. Two
/// shapes need more care. When `&&` or `||` comes before the loop it may be
/// skipped, while the written-out list skips only its first command, so a body
/// that changes the directory or another piece of shell state would make the
/// later steps look as if they ran somewhere else; that body keeps its review.
/// When `&&` or `||` comes after `done`, it reads the status of the body's last
/// command, so a `!` there cannot be dropped and keeps the review.
pub(super) fn unroll_in_list<'a>(
    command: &'a str,
    home_dir: Option<&str>,
    gated: bool,
) -> Option<(String, &'a str)> {
    unrolled(command, home_dir, Place::InList { gated })
}

fn unrolled<'a>(
    command: &'a str,
    home_dir: Option<&str>,
    place: Place,
) -> Option<(String, &'a str)> {
    let home = home_dir
        .map(|home| home.trim_end_matches('/'))
        .filter(|home| home.starts_with('/') && home.len() > 1 && safe_value(home));
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
    let (mut words, rest) = header_words(rest, home)?;
    if words.is_empty() {
        return None;
    }
    let rest = rest.trim_start_matches([' ', '\t', '\n', ';']);
    let rest = keyword(rest, "do")?;
    let (items, _, after) = body_items(rest, name, &["done"])?;
    let (piped, tail, rest) = match place {
        Place::Alone => {
            // A pipe into text filters after `done` reads the whole loop's
            // output as one stream, which is the unrolled list in a brace
            // group piped the same way. `piped_group` decides that group.
            let piped = super::piped_group::filter_tail(after);
            // `cd DIR && for ...; done | FILTER` runs the filters in DIR, but
            // the group would carry the `cd` inside it and the filters would
            // be proved in the caller's directory, so that shape keeps its
            // review.
            if piped.is_some() && !prefix.is_empty() {
                return None;
            }
            let tail = match piped {
                Some(_) => String::new(),
                None => redirect_tail(after)?,
            };
            (piped, tail, "")
        }
        Place::InList { gated } => {
            let rest = after.trim_start_matches([' ', '\t']);
            let joined = rest.starts_with("&&") || rest.starts_with("||");
            if !(rest.is_empty()
                || joined
                || (rest.starts_with([';', '\n']) && !rest.starts_with(";;")))
            {
                return None;
            }
            let last_negated = items
                .last()
                .is_some_and(|(text, _)| text.trim_start().starts_with('!'));
            let changes_state = !prefix.is_empty()
                || items
                    .iter()
                    .any(|(text, _)| super::control_flow_chain::changes_shell_state(text));
            if (joined && last_negated) || (gated && changes_state) {
                return None;
            }
            (None, String::new(), rest)
        }
    };
    if items.is_empty() || items.iter().any(|(text, _)| rebinds(text, name)) {
        return None;
    }
    // A body that never reads the loop variable runs the same text on every
    // pass, so one written-out pass is the work every pass does, however many
    // words the header holds. `for n in {1..60}; do sleep 5; done` is
    // `sleep 5` sixty times. That holds only while a pass leaves nothing the
    // next one reads: `cd ..` run five times climbs five directories, and one
    // written-out `cd ..` would prove the later commands in the wrong place.
    // A body that reads the variable, or carries shell state from pass to
    // pass, is written out once per word, which the word bound keeps finite.
    let same_every_pass = !items
        .iter()
        .any(|(text, _)| body::reads_the_variable(text) || carries_state(text));
    if same_every_pass {
        words.truncate(1);
    } else if words.len() > MAX_WORDS {
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
        // The unrolled list runs the items the loop ran. A leading `!` only
        // inverts an item's exit status, so it is dropped wherever the
        // separator after it shows nothing reads that outcome. An `if … fi`
        // statement is written out whole as one step.
        for (step, separator) in conditional::written_steps(&items, word, &tail)? {
            out.push_str(&step);
            out.push_str(separator);
        }
        if out.len() > MAX_UNROLLED_BYTES {
            return None;
        }
    }
    let trimmed = out.trim_end_matches([' ', ';']);
    Some((
        match piped {
            Some(filters) => format!("{{ {trimmed}; }} | {filters}"),
            None => trimmed.to_owned(),
        },
        rest,
    ))
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
/// A pattern that starts at the root, or at the home directory a leading `~/`
/// names, is handed to the body as the same absolute word, so the body's
/// proofs decide it exactly as they decide `cat /etc/*.conf` or
/// `cat ~/.aws/*` written out, both of which keep their review there. A
/// pattern that reaches above the working directory with `..` keeps its
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
        && !value.starts_with(['-', '['])
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
fn header_words<'a>(text: &'a str, home: Option<&str>) -> Option<(Vec<String>, &'a str)> {
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
            // An unquoted `~/` opening a word is the home directory.
            '~' if !in_word && chars.peek().is_some_and(|(_, next)| *next == '/') => {
                current.push_str(home?);
                in_word = true;
            }
            // A whole unquoted word such as `{1..60}` is a sequence the shell
            // writes out as its numbers before the loop runs.
            '{' if !in_word => {
                let (numbers, length) = sequence(&text[index..])?;
                words.extend(numbers.into_iter().map(|number| (number, false)));
                for _ in 1..length {
                    chars.next();
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

/// The most digits a sequence bound may have, which bounds how many passes a
/// sequence names.
const MAX_SEQUENCE_DIGITS: usize = 6;

/// A brace sequence `{FIRST..LAST}` or `{FIRST..LAST..STEP}` of plain numbers
/// standing as a whole word, as bash and zsh both expand it: every number from
/// FIRST to LAST, counting down when LAST is smaller. It returns the numbers,
/// up to one more than [`MAX_WORDS`] so a longer sequence still reads as too
/// long to write out per word, and the length of the text it consumed.
///
/// A bound with a leading zero pads every number to its width and a signed
/// bound counts through zero; neither is read here, so both keep the review,
/// as does any other text in braces.
fn sequence(text: &str) -> Option<(Vec<String>, usize)> {
    let close = text.find('}')?;
    let after = text[close + 1..].chars().next();
    if !matches!(after, None | Some(' ' | '\t' | '\n' | ';')) {
        return None;
    }
    let parts: Vec<&str> = text[1..close].split("..").collect();
    let number = |part: &str| {
        (!part.is_empty()
            && part.len() <= MAX_SEQUENCE_DIGITS
            && part.bytes().all(|byte| byte.is_ascii_digit())
            && (part == "0" || !part.starts_with('0')))
        .then(|| part.parse::<u64>().ok())
        .flatten()
    };
    let (first, last, step) = match parts.as_slice() {
        [first, last] => (number(first)?, number(last)?, 1),
        [first, last, step] => (number(first)?, number(last)?, number(step)?),
        _ => return None,
    };
    if step == 0 {
        return None;
    }
    let count = first.abs_diff(last) / step + 1;
    let numbers = (0..count.min(MAX_WORDS as u64 + 1))
        .map(|pass| {
            if first <= last {
                first + pass * step
            } else {
                first - pass * step
            }
            .to_string()
        })
        .collect();
    Some((numbers, close + 1))
}

/// `valid_identifier` already limits loop variables to lowercase names. The
/// `*_proxy` names are lowercase environment variables, and the zsh specials
/// change shell state, so binding either changes what the body would run.
pub(super) fn ordinary_loop_name(name: &str) -> bool {
    !name.ends_with("_proxy") && !SHELL_SPECIAL_NAMES.contains(&name)
}

/// Whether one body item can change shell state a later pass reads: a state
/// builtin such as `cd` or `export`, read through the keyword that opens a
/// conditional's part (`if cd ..`, `then export X=1`), or a construct this
/// check does not look inside. A bare `then`, `else` or `fi` changes nothing.
fn carries_state(item: &str) -> bool {
    let text = item.trim();
    if matches!(text, "then" | "else" | "fi") {
        return false;
    }
    let command = ["if", "elif", "then", "else"]
        .into_iter()
        .find_map(|opener| super::control_flow_flatten::keyword(text, opener))
        .unwrap_or(text);
    super::control_flow_chain::changes_shell_state(command)
}
