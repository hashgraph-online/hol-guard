//! Globs that a program prints instead of listing.
//!
//! An unquoted glob is a directory listing whichever program receives it:
//! `echo ~/.aws/*` prints the names `ls ~/.aws` would. A program that only
//! prints its words therefore takes the proof a non-recursive `ls` of the same
//! pattern takes. A variable bound to a glob is expanded at a later bare
//! `$NAME`, where quotes in the binding no longer apply, so the binding carries
//! that proof itself: `P=~/.ssh/id_*; echo $P` lists the private keys. A word
//! that splices the variable into other text, as `~/.ssh/$P` does, globs under
//! a prefix the binding's proof never saw, so it has no proof.

use crate::{CanonicalCommandV1, CommandSegmentV1};
use std::path::Path;

const GLOB: [char; 3] = ['*', '?', '['];

/// Where the literal part of a word ends: a glob or an expansion.
const OPEN: [char; 5] = ['*', '?', '[', '$', '`'];

/// Programs whose words reach the terminal, on success or in an error.
const PRINTERS: [&str; 9] = [
    "pwd", "true", "echo", "printf", "which", "whoami", "uname", "dirname", "basename",
];

/// One shell word: its quote-removed value, whether an unquoted glob in it
/// expands, and whether an unquoted expansion is spliced into other text.
struct Word {
    value: String,
    glob: bool,
    spliced: bool,
}

/// Each glob argument of a printing segment is one a listing may show.
pub(super) fn printed_globs_listable(
    model: &CanonicalCommandV1,
    segment: &CommandSegmentV1,
    context: super::PathContext<'_>,
) -> bool {
    printed_globs(segment, globbed_binding(model))
        .into_iter()
        .all(|value| listable(value, context))
}

/// Each glob a binding holds is one a listing may show. Quotes in a binding
/// keep `~` literal, which the listing proof would expand, so a quoted glob
/// binding has no proof. The listing proof screens every match, so the
/// pattern itself needs no name screen.
pub(super) fn bound_globs_listable<'a>(
    segment: &CommandSegmentV1,
    values: impl IntoIterator<Item = &'a str>,
    context: super::PathContext<'_>,
) -> bool {
    values
        .into_iter()
        .filter(|value| value.contains(GLOB))
        .all(|value| !segment.text.contains(['\'', '"', '\\']) && listable(value, context))
}

/// A printed or bound glob that reaches a credential location, or a hidden
/// directory or hidden-name pattern outside the project. Listing it is the
/// access the sensitive screen asks about, not routine work to contain. A
/// glob built on a variable reaches wherever a binding in the command points
/// it. Hidden names inside the project keep the containment `ls` gets.
pub(super) fn names_hidden_glob(
    model: &CanonicalCommandV1,
    context: super::PathContext<'_>,
) -> bool {
    let bindings = bindings(model);
    let globbed = bindings.iter().any(|binding| binding.contains(GLOB));
    let reaches = |value: &str| {
        hidden_reach(value)
            || (value.contains('$') && bindings.iter().any(|binding| bound_location(binding)))
    };
    model.segments.iter().any(|segment| {
        let globs: Vec<&str> = match segment
            .executable
            .as_deref()
            .map(super::executable_basename)
        {
            None => binding_values(&segment.tokens)
                .filter(|value| value.contains(GLOB))
                .collect(),
            Some("export") => binding_values(&segment.arguments)
                .filter(|value| value.contains(GLOB))
                .collect(),
            Some(name) if PRINTERS.contains(&name) => printed_globs(segment, globbed),
            Some(_) => Vec::new(),
        };
        globs
            .into_iter()
            .filter(|value| !listable(value, context))
            .any(&reaches)
    })
}

/// The values of `NAME=value` words.
pub(super) fn binding_values(words: &[String]) -> impl Iterator<Item = &str> {
    words
        .iter()
        .filter_map(|word| word.split_once('=').map(|(_, value)| value))
}

/// The values the command's assignments and exports bind.
fn bindings(model: &CanonicalCommandV1) -> Vec<&str> {
    model
        .segments
        .iter()
        .flat_map(|segment| match segment.executable.as_deref() {
            None => binding_values(&segment.tokens).collect(),
            Some(executable) if super::executable_basename(executable) == "export" => {
                binding_values(&segment.arguments).collect()
            }
            Some(_) => Vec::new(),
        })
        .collect()
}

fn globbed_binding(model: &CanonicalCommandV1) -> bool {
    bindings(model).iter().any(|binding| binding.contains(GLOB))
}

/// A listing may show the glob's names. A hidden-name pattern prints names
/// the hidden-path screen guards, whatever the listing proof would allow.
fn listable(value: &str, context: super::PathContext<'_>) -> bool {
    !value.contains(['$', '`'])
        && !split_open(value).is_some_and(|(_, pattern)| hidden_pattern(pattern))
        && (super::listing_reads::listable_glob(value, context)
            || super::search::glob_matches_nothing(value, context))
}

fn hidden_reach(value: &str) -> bool {
    let value = home_spelled(value);
    let Some((directory, pattern)) = split_open(&value) else {
        return false;
    };
    (outside_project(&value) && hidden_pattern(pattern))
        || (!directory.is_empty() && sensitive_location(directory))
}

/// A binding whose literal part names a credential or hidden location outside
/// the project, so a glob built on it lists there.
fn bound_location(value: &str) -> bool {
    let value = home_spelled(value);
    let literal = value
        .find(OPEN)
        .map_or(value.as_str(), |first| &value[..first]);
    sensitive_location(literal.trim_end_matches('/'))
}

/// The directory before the first glob or expansion in `value`, and the rest.
fn split_open(value: &str) -> Option<(&str, &str)> {
    let first = value.find(OPEN)?;
    let directory = value[..first]
        .rsplit_once('/')
        .map_or("", |(directory, _)| directory);
    Some((directory, value[directory.len()..].trim_start_matches('/')))
}

fn hidden_pattern(pattern: &str) -> bool {
    pattern.split('/').any(|part| part.starts_with('.'))
}

/// A path outside the working tree: under home, absolute, through `..`, or
/// built on a variable.
fn outside_project(value: &str) -> bool {
    value.starts_with(['~', '/', '$']) || value.split('/').any(|part| part == "..")
}

/// A literal location the sensitive screen guards, or a hidden directory
/// outside the project that reads may not enter. The name screen sees no
/// wildcard: one can spell a credential name anywhere, so screening it would
/// flag every project glob.
fn sensitive_location(literal: &str) -> bool {
    super::sensitive_read_path_argument(literal)
        || (outside_project(literal)
            && !guard_secure_fs::hidden_read_parts_allowed(Path::new(literal)))
}

/// `$HOME` spelled as `~`, so home locations read alike either way.
fn home_spelled(value: &str) -> String {
    ["${HOME}", "$HOME"]
        .iter()
        .find_map(|home| value.strip_prefix(home))
        .filter(|rest| rest.is_empty() || rest.starts_with('/'))
        .map_or_else(|| value.to_owned(), |rest| format!("~{rest}"))
}

/// The arguments the shell globs. With a glob bound in the command, a word
/// that splices an expansion into other text globs too. Without a quote map
/// every glob character counts as unquoted. Words after a comment are not
/// arguments.
fn printed_globs(segment: &CommandSegmentV1, globbed_binding: bool) -> Vec<&str> {
    let (words, commented) = words(&segment.text).unwrap_or_default();
    let mut remaining = words.iter();
    segment
        .arguments
        .iter()
        .filter(
            |argument| match remaining.find(|word| word.value == **argument) {
                Some(word) => word.glob || (globbed_binding && word.spliced),
                None => {
                    !commented
                        && (argument.contains(GLOB) || (globbed_binding && argument.contains('$')))
                }
            },
        )
        .map(String::as_str)
        .collect()
}

/// The words of `text` before any comment, and whether a comment ended them.
/// `None` when a quote is left open.
fn words(text: &str) -> Option<(Vec<Word>, bool)> {
    let mut words = Vec::new();
    let mut value = String::new();
    let mut glob = false;
    let mut open = false;
    let mut expands = false;
    let mut bare = false;
    let mut characters = text.chars().peekable();
    while let Some(character) = characters.next() {
        match character {
            ' ' | '\t' | '\n' => {
                if open {
                    words.push(Word {
                        value: std::mem::take(&mut value),
                        glob,
                        spliced: expands && !bare,
                    });
                }
                glob = false;
                open = false;
                expands = false;
                bare = false;
                continue;
            }
            '#' if !open => return Some((words, true)),
            '\'' => loop {
                match characters.next()? {
                    '\'' => break,
                    quoted => value.push(quoted),
                }
            },
            '"' => loop {
                match characters.next()? {
                    '"' => break,
                    '\\' => match characters.next()? {
                        escaped @ ('$' | '`' | '"' | '\\') => value.push(escaped),
                        '\n' => {}
                        other => {
                            value.push('\\');
                            value.push(other);
                        }
                    },
                    quoted => value.push(quoted),
                }
            },
            '\\' => value.push(characters.next()?),
            '`' => {
                expands = true;
                value.push('`');
                loop {
                    let quoted = characters.next()?;
                    value.push(quoted);
                    if quoted == '`' {
                        break;
                    }
                }
            }
            '$' => {
                expands = true;
                value.push('$');
                glob |= expansion(&mut characters, &mut value)?;
            }
            other => {
                glob |= GLOB.contains(&other);
                value.push(other);
            }
        }
        // A bare word is one expansion and nothing else.
        bare = !open && character == '$';
        open = true;
    }
    if open {
        words.push(Word {
            value,
            glob,
            spliced: expands && !bare,
        });
    }
    Some((words, false))
}

/// Copies the rest of a `$` expansion, whose characters the shell does not
/// glob while it reads them: `$?`, `$#`, `$((2*3))`. A `${...}` holding a
/// glob character can expand to one, as `${P:-*}` does when `P` is unset, and
/// the shell then globs the unquoted result.
fn expansion(
    characters: &mut std::iter::Peekable<std::str::Chars<'_>>,
    value: &mut String,
) -> Option<bool> {
    let close = match characters.peek() {
        Some('{') => '}',
        Some('(') => ')',
        Some(special) if "?*#@$!-0123456789".contains(*special) => {
            value.push(characters.next()?);
            return Some(false);
        }
        _ => {
            while let Some(name) = characters.next_if(|c| c.is_ascii_alphanumeric() || *c == '_') {
                value.push(name);
            }
            return Some(false);
        }
    };
    let open = characters.next()?;
    value.push(open);
    let start = value.len();
    let mut depth = 1_usize;
    while depth > 0 {
        let next = characters.next()?;
        if next == open {
            depth += 1;
        } else if next == close {
            depth -= 1;
        }
        value.push(next);
    }
    Some(close == '}' && value[start..].contains(GLOB))
}

#[cfg(test)]
mod tests {
    use super::words;

    #[test]
    fn quoted_and_expanded_glob_characters_are_not_globs() {
        let (words, commented) =
            words(r#"echo "a*" 'b?' c\* $? ${P:-*} $((2*3)) d* "$(e)"f[x]"#).unwrap();
        let globs: Vec<bool> = words.iter().map(|word| word.glob).collect();
        assert_eq!(
            globs,
            [false, false, false, false, false, true, false, true, true]
        );
        assert!(!commented);
        assert_eq!(words[1].value, "a*");
        assert_eq!(words[3].value, "c*");
        assert_eq!(words[8].value, "$(e)f[x]");
    }

    #[test]
    fn only_a_bare_expansion_keeps_its_binding() {
        let (words, _) = words(r#"echo $P ${P} "$P" ~/.ssh/$P $P/x x`y`"#).unwrap();
        let spliced: Vec<bool> = words.iter().map(|word| word.spliced).collect();
        assert_eq!(spliced, [false, false, false, false, true, true, true]);
    }

    #[test]
    fn a_comment_ends_the_words() {
        let (words, commented) = words("echo a#b ok # ~/.ssh/*").unwrap();
        let values: Vec<&str> = words.iter().map(|word| word.value.as_str()).collect();
        assert_eq!(values, ["echo", "a#b", "ok"]);
        assert!(commented);
    }

    #[test]
    fn an_open_quote_has_no_words() {
        assert!(words("echo 'a*").is_none());
        assert!(words("echo \"a*").is_none());
    }
}
