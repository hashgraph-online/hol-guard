//! Steps proven to write nothing, whatever they read.
//!
//! A step that runs before a Git read needs only a write proof
//! (`git_read_floor`): what it prints is judged as its own command, while a
//! file it writes could change the configuration the read runs with. These
//! readers take no option that names a file to write, once their programs
//! and expressions are screened, so where their operands point is not this
//! module's question.

/// Whether this `find` or `sed` writes nothing.
///
/// Every word must reach the program as written (`words_as_written`), and a
/// redirect that names a file keeps review.
pub(super) fn writes_nothing(segment: &crate::CommandSegmentV1) -> bool {
    let quiet = ["2>&1", "2>/dev/null", ">/dev/null"]
        .iter()
        .fold(segment.text.clone(), |text, quiet| text.replace(quiet, ""));
    if quiet.contains('>')
        || !segment.wrapper_chain.is_empty()
        || segment.path_overridden
        || !words_as_written(&segment.text)
    {
        return false;
    }
    match segment.executable.as_deref() {
        Some("find") => super::find_reads::expression_writes_nothing(&segment.arguments),
        Some("sed") => super::safe_reads::sed_writes_nothing(&segment.arguments),
        _ => false,
    }
}

/// Whether the shell hands every word over as written: no unquoted glob or
/// brace list (an unquoted `*` can expand to a file named `-delete`), no
/// unquoted escape, and no expansion but a double-quoted `$HOME` path, which
/// the shell can neither split nor turn into an option.
fn words_as_written(text: &str) -> bool {
    let mut plain = String::with_capacity(text.len());
    let mut quote: Option<char> = None;
    let mut rest = text;
    while let Some(character) = rest.chars().next() {
        rest = &rest[character.len_utf8()..];
        plain.push(character);
        match quote {
            Some(open) if character == open => quote = None,
            // `quoted_words` refuses an escape outside quotes, so the
            // character after one never reaches this scan as a quote.
            Some('"') if character == '\\' => {
                if let Some(escaped) = rest.chars().next() {
                    rest = &rest[escaped.len_utf8()..];
                    plain.push(escaped);
                }
            }
            Some(_) => {}
            None if character == '\'' => quote = Some(character),
            None if character == '"' => {
                quote = Some(character);
                for home in ["${HOME}", "$HOME"] {
                    if let Some(after) = rest.strip_prefix(home) {
                        if home == "${HOME}" || after.starts_with(['/', '"']) {
                            plain.push_str("/home");
                            rest = after;
                        }
                        break;
                    }
                }
            }
            None => {}
        }
    }
    super::listing_reads::quoted_words(&plain).is_some_and(|words| {
        words
            .iter()
            .all(|word| !word.unquoted_glob && !word.unquoted_expansion)
    })
}

#[cfg(test)]
#[path = "write_free_steps_tests.rs"]
mod tests;
