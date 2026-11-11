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
        || matches!(delimiter, '\\' | ';' | '[' | ']')
    {
        return None;
    }
    let mut offset = delimiter.len_utf8();
    offset += regex_end(&body[offset..], delimiter)? + delimiter.len_utf8();
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
            return sed_substitution_flags_rest(&body[offset..]);
        }
    }
    None
}

/// Where a regex ends: the byte offset of the delimiter that closes it.
///
/// sed implementations disagree about a delimiter inside a bracket
/// expression. BSD sed skips the whole bracket when it looks for the closing
/// delimiter, while GNU sed stops at the first unescaped one. A bracket here
/// is read the POSIX way -- a leading `^` and `]` are members, and `[:`, `[.`
/// and `[=` open a class that only `:]`, `.]` or `=]` closes -- and one that
/// holds the delimiter or a backslash, or never closes, is refused. Both
/// readings then end the regex at the same place.
fn regex_end(body: &str, delimiter: char) -> Option<usize> {
    let mut characters = body.char_indices();
    while let Some((index, character)) = characters.next() {
        match character {
            '\\' => {
                characters.next()?;
            }
            '[' => skip_bracket(&mut characters, delimiter)?,
            _ if character == delimiter => return Some(index),
            _ => {}
        }
    }
    None
}

/// Consumes a bracket expression after its `[`. `None` when it never closes
/// or holds a character the two delimiter readings could split on.
fn skip_bracket(characters: &mut std::str::CharIndices<'_>, delimiter: char) -> Option<()> {
    let mut member = || {
        characters
            .next()
            .map(|(_, character)| character)
            .filter(|character| *character != delimiter && *character != '\\')
    };
    let mut character = member()?;
    if character == '^' {
        character = member()?;
    }
    // A `]` first in the list is a member, not the end.
    if character == ']' {
        character = member()?;
    }
    let mut previous = None;
    loop {
        match (previous, character) {
            (Some('['), ':' | '.' | '=') => {
                let kind = character;
                let mut last = member()?;
                loop {
                    let next = member()?;
                    if last == kind && next == ']' {
                        break;
                    }
                    last = next;
                }
                previous = None;
            }
            (_, ']') => return Some(()),
            _ => previous = Some(character),
        }
        character = member()?;
    }
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
/// Upper bound on statements in one stream-edit script.
const MAX_STREAM_STATEMENTS: usize = 16;

/// A script whose every statement edits only the stream it reads.
///
/// Trimming a listing is spelled with more than a substitution:
/// `sed '1d;$d'` drops a header and a footer, `sed '/^#/d'` drops comments,
/// `sed 5q` stops after five lines and `sed '12s/a/b/'` rewrites one line.
/// Each statement takes an optional address or address range -- a line
/// number, `$`, or a plain `/regex/` -- an optional `!`, and one of `d`, `p`,
/// `q`, `Q`, `=` or a substitution. All of them print, drop or rewrite lines
/// of the input and nothing else. The commands that reach past the stream --
/// `w`/`W` write a file, `r`/`R` read one, `e` runs a shell -- and every
/// block, label, branch, hold-space or text command are not in that list, so
/// a script that spells one stays unread and keeps its review.
pub(crate) fn sed_script_is_stream_edit(script: &str) -> bool {
    let mut rest = py_strip(script);
    if rest.is_empty() {
        return false;
    }
    for _ in 0..MAX_STREAM_STATEMENTS {
        let Some(after) = stream_statement_rest(rest) else {
            return false;
        };
        rest = py_strip(after);
        let Some(next) = rest.strip_prefix(';') else {
            return rest.is_empty();
        };
        // A trailing `;` is refused, as the line-range reading refuses it.
        rest = py_strip(next);
        if rest.is_empty() {
            return false;
        }
    }
    false
}

/// One stream statement, and the script text left after it.
fn stream_statement_rest(text: &str) -> Option<&str> {
    let mut rest = text;
    if let Some((first, after)) = address_rest(rest) {
        rest = after.trim_start_matches([' ', '\t']);
        if let Some(after_comma) = rest.strip_prefix(',') {
            let (second, after) = address_rest(after_comma.trim_start_matches([' ', '\t']))?;
            // Line 0 only opens a range that a pattern closes (`0,/re/`).
            if second == Address::Zero || (first == Address::Zero && second != Address::Pattern) {
                return None;
            }
            rest = after;
        } else if first == Address::Zero {
            return None;
        }
        rest = rest.trim_start_matches([' ', '\t']);
        rest = rest.strip_prefix('!').unwrap_or(rest);
        rest = rest.trim_start_matches([' ', '\t']);
    }
    let after = match rest.chars().next()? {
        'd' | 'p' | '=' => &rest[1..],
        'q' | 'Q' => rest[1..].trim_start_matches(|c: char| c.is_ascii_digit()),
        's' => sed_substitution_rest(rest)?,
        _ => return None,
    };
    // A command ends at `;`, at blank space, or at the end of the script.
    (after.is_empty() || after.starts_with(';') || after.starts_with([' ', '\t'])).then_some(after)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Address {
    Zero,
    Line,
    Pattern,
}

/// One address -- a line number, `$`, or a `/regex/` with optional `I`/`M`
/// flags -- and the text after it. A bracket expression holding the `/` is
/// refused rather than guessed at, since sed implementations disagree on
/// whether it closes the address.
fn address_rest(text: &str) -> Option<(Address, &str)> {
    if let Some(after) = text.strip_prefix('$') {
        return Some((Address::Line, after));
    }
    let digits = text.len() - text.trim_start_matches(|c: char| c.is_ascii_digit()).len();
    if digits > 0 {
        if digits > 6 {
            return None;
        }
        let line = text[..digits].parse::<u32>().ok()?;
        let kind = if line == 0 {
            Address::Zero
        } else {
            Address::Line
        };
        return Some((kind, &text[digits..]));
    }
    let body = text.strip_prefix('/')?;
    // An empty `//` reuses the last regex, which this reading never saw.
    let end = regex_end(body, '/').filter(|end| *end > 0)?;
    let after = body[end + 1..].trim_start_matches(['I', 'M']);
    Some((Address::Pattern, after))
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
        // BSD sed skips a bracket expression when it looks for the
        // delimiter and GNU sed does not, so a bracket holding the delimiter
        // splits the script in two different places.
        assert!(sed_script_is_pure_substitution("s/[a-z]/x/"));
        assert!(sed_script_is_pure_substitution("s/[]a]/x/;s/[^]a]/y/"));
        assert!(sed_script_is_pure_substitution("s/[[:space:]]*$//"));
        assert!(!sed_script_is_pure_substitution("s@[@]@;s@w copy@x@"));
        assert!(!sed_script_is_pure_substitution("s/[/]/x/"));
        assert!(!sed_script_is_pure_substitution("s:[[:space:]]::"));
        assert!(!sed_script_is_pure_substitution(r"s/[\]]/x/"));
        assert!(!sed_script_is_pure_substitution("s/[abc/x/"));
    }

    /// A bracket expression is read the POSIX way, and one the delimiter
    /// readings could split differently keeps the review.
    #[test]
    fn a_stream_edit_address_bracket_never_hides_its_delimiter() {
        assert!(sed_script_is_stream_edit("/[0-9]/d"));
        assert!(sed_script_is_stream_edit("/^[[:space:]]*$/d"));
        assert!(sed_script_is_stream_edit("/[]x]/d;/[^]x]/p"));
        assert!(sed_script_is_stream_edit("/[[.-.]]/d"));
        assert!(!sed_script_is_stream_edit("/[]/d;s/]/w out/g"));
        assert!(!sed_script_is_stream_edit("/[[:space:]/p;s/]/w src/g"));
        assert!(!sed_script_is_stream_edit("/[]/d; s/]/e printf x #/"));
        assert!(!sed_script_is_stream_edit("/[]/d;s#]/w out#x#"));
        assert!(!sed_script_is_stream_edit("1s@[@]@;s@w copy@x@"));
        assert!(!sed_script_is_stream_edit("//d"));
    }
}
