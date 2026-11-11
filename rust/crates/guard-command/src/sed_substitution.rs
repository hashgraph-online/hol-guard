//! The reading that follows a `sed` substitution to its end.
//!
//! A redaction in the middle of a read-only pipeline -- `sed -E
//! 's/\/tmp\/scratch-[a-z0-9]+/TMPDIR/'` -- rewrites the text it reads and
//! writes it on, so the pipeline around it is no less read-only than one built
//! from `cat` and `sort`. Reading that program by splitting it on its
//! delimiter cannot tell the delimiter from the one a pattern escapes inside
//! itself, so this walks the program instead.

use crate::codex_output_py::py_strip;

/// A script that only rewrites the text of the lines it reads.
///
/// `sed -E 's/token/REDACTED/g'` in the middle of a pipeline reads its input
/// and writes the rewritten text, exactly like the bounded print this reading
/// already follows, so a pipeline built from it is no less read-only. The
/// commands that are not a substitution are the ones that reach past the
/// stream: `w` and `W` write a file, `r` and `R` read one into the output, and
/// `e` hands the pattern space to a shell. None of them spell an `s`, so
/// admitting only a substitution leaves every one of them to review.
pub(crate) fn sed_script_is_pure_substitution(script: &str) -> bool {
    let mut rest = py_strip(script);
    if rest.is_empty() {
        return false;
    }
    loop {
        let Some(after) = sed_substitution_rest(rest) else {
            return false;
        };
        rest = py_strip(after);
        let Some(next) = rest.strip_prefix(';') else {
            return rest.is_empty();
        };
        rest = py_strip(next);
        if rest.is_empty() {
            return true;
        }
    }
}

/// One substitution, and the script text left after it.
///
/// A substitution spells `s`, a delimiter, the pattern, the delimiter, the
/// replacement, the delimiter, and its flags. The delimiter is whatever
/// character follows the `s`, so the walk counts two more of that character
/// while honouring the backslash that escapes one inside a pattern -- a
/// redaction such as `s/\/tmp\/scratch-[a-z]*/TMPDIR/` carries several. A
/// script that never closes its second delimiter is one this reading never
/// finished, so it comes back unread and keeps its review.
fn sed_substitution_rest(text: &str) -> Option<&str> {
    let body = text.strip_prefix('s')?;
    let delimiter = body.chars().next()?;
    if delimiter.is_alphanumeric()
        || delimiter.is_whitespace()
        || delimiter == '\\'
        || delimiter == ';'
    {
        return None;
    }
    let mut offset = delimiter.len_utf8();
    let mut closed = 0usize;
    let mut escaped = false;
    for character in body[offset..].chars() {
        offset += character.len_utf8();
        if escaped {
            escaped = false;
            continue;
        }
        if character == '\\' {
            escaped = true;
            continue;
        }
        if character == delimiter {
            closed += 1;
            if closed == 2 {
                return sed_substitution_flags_rest(&body[offset..]);
            }
        }
    }
    None
}

/// The flags a substitution carries, and the script text left after them.
///
/// `g`, `p`, a case-insensitive `i`/`I`, a multiline `m`/`M` and an occurrence
/// count all stay inside the stream. The two that do not are `w`, which writes
/// the rewritten line to a file named after it, and `e`, which runs the
/// pattern space as a shell command; both are refused here along with anything
/// else this reading does not know.
fn sed_substitution_flags_rest(text: &str) -> Option<&str> {
    for (index, character) in text.char_indices() {
        match character {
            'g' | 'p' | 'i' | 'I' | 'm' | 'M' => continue,
            _ if character.is_ascii_digit() => continue,
            ';' => return Some(&text[index..]),
            _ if character.is_whitespace() => return Some(&text[index..]),
            _ => return None,
        }
    }
    Some("")
}
#[cfg(test)]
mod tests {
    use super::*;

    /// The substitution reading, down to the characters that leave the stream.
    #[test]
    fn a_substitution_script_rewrites_only_the_text_it_reads() {
        assert!(sed_script_is_pure_substitution("s/alpha/beta/"));
        assert!(sed_script_is_pure_substitution("s/alpha/beta/g"));
        assert!(sed_script_is_pure_substitution("s/alpha/beta/2gpI"));
        assert!(sed_script_is_pure_substitution("s|/one/two|/three/|g"));
        assert!(sed_script_is_pure_substitution(
            r"s/\/tmp\/scratch-[a-z0-9]+/TMPDIR/"
        ));
        assert!(sed_script_is_pure_substitution("s/a/b/ ; s/c/d/g"));
        assert!(sed_script_is_pure_substitution("s/a/b/;"));
        // `w` names a file to write, `e` hands the pattern space to a shell,
        // and `r` reads a file into the output. None of them stay in the
        // stream, so none of them settle here.
        assert!(!sed_script_is_pure_substitution("s/a/b/w captured.txt"));
        assert!(!sed_script_is_pure_substitution("s/a/b/e"));
        assert!(!sed_script_is_pure_substitution("s/a/b/; r /etc/hosts"));
        assert!(!sed_script_is_pure_substitution("s/a/b/; w captured.txt"));
        assert!(!sed_script_is_pure_substitution("1,5p"));
        assert!(!sed_script_is_pure_substitution(""));
        // A substitution that never closes is one this reading never
        // finished, so it keeps its review.
        assert!(!sed_script_is_pure_substitution("s/alpha/beta"));
        assert!(!sed_script_is_pure_substitution(r"s/alpha/beta\/"));
    }
}
