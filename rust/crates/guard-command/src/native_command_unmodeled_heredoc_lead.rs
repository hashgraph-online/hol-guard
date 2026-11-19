//! Where the command a heredoc feeds begins, when the text before it on the
//! same line holds quoted words.
//!
//! `cd 'my dir' && python3 - <<'EOF'` feeds the heredoc to `python3`, exactly
//! as `cd my-dir && python3 - <<'EOF'` does. The heredoc reader refused any
//! quote before `<<`, because a quoted `;` or `&&` is not an operator and
//! splitting there would name the wrong program. The refusal reached an
//! evaluation failure, which blocks with no approval left to give, while the
//! unquoted spelling of the same command reached review.
//!
//! This scan follows plain single and double quotes so an operator inside one
//! is not read as a split. Quoting it does not follow keeps the refusal: an
//! ANSI-C or locale string, a substitution or backtick (whose own quotes nest
//! inside a double-quoted word), and a quote left open, including one opened
//! on an earlier line.

/// The byte offset in `before` just past the last operator the shell reads as
/// one, or 0 when none. `earlier` is the text already read on lines before
/// this one, used only to tell whether a quote is still open.
///
/// `None` when a quote is left open, when the command after the split holds a
/// quote of its own, or when the text holds quoting this scan does not follow.
pub(super) fn command_start(earlier: &str, before: &str) -> Option<usize> {
    let quoted = |text: &str| text.contains(['\'', '"']);
    if !quoted(earlier) && !quoted(before) {
        return Some(split_at(before));
    }
    for text in [earlier, before] {
        if text.contains('`') || text.contains("$(") || text.contains("$'") || text.contains("$\"")
        {
            return None;
        }
    }
    if open_quote(earlier) {
        return None;
    }
    let (mut quote, mut escaped, mut start) = (None, false, 0usize);
    for (at, character) in before.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match quote {
            Some(open) if character == open => quote = None,
            Some('"') if character == '\\' => escaped = true,
            Some(_) => {}
            None => match character {
                '\'' | '"' => quote = Some(character),
                '\\' => escaped = true,
                ';' | '&' | '|' | '(' => start = at + 1,
                _ => {}
            },
        }
    }
    if quote.is_some() || escaped || quoted(&before[start..]) {
        return None;
    }
    Some(start)
}

/// The split the reader made before quotes were followed, for text without
/// any.
fn split_at(before: &str) -> usize {
    before.rfind([';', '&', '|', '(']).map_or(0, |at| at + 1)
}

/// Whether `text` ends inside a quote or after a lone backslash.
fn open_quote(text: &str) -> bool {
    let (mut quote, mut escaped) = (None, false);
    for character in text.chars() {
        if escaped {
            escaped = false;
            continue;
        }
        match quote {
            Some(open) if character == open => quote = None,
            Some('"') if character == '\\' => escaped = true,
            Some(_) => {}
            None => match character {
                '\'' | '"' => quote = Some(character),
                '\\' => escaped = true,
                _ => {}
            },
        }
    }
    quote.is_some() || escaped
}

#[cfg(test)]
mod tests {
    use super::command_start;

    #[test]
    fn a_quoted_word_before_the_command_is_followed() {
        for (before, command) in [
            ("cd 'my dir' && python3 - ", "python3 - "),
            ("cd \"src\"; python3 ", "python3 "),
            ("echo 'a;b' && cat ", "cat "),
            ("echo \"a \\\" && b\" | cat ", "cat "),
            ("cd src && python3 ", "python3 "),
            ("python3 ", "python3 "),
        ] {
            let start = command_start("", before).unwrap_or_else(|| panic!("{before}"));
            assert_eq!(before[start..].trim_start(), command, "{before}");
        }
    }

    #[test]
    fn quoting_it_does_not_follow_is_refused() {
        for (earlier, before) in [
            // A quote opened on an earlier line is still open here.
            ("echo 'a", "b'' && python3 "),
            ("", "echo 'a && python3 "),
            ("", "echo \"$(echo \")\")\" && python3 "),
            ("", "echo `printf \"'\"` && python3 "),
            ("", "echo $'it\\'s' && python3 "),
            ("", "echo $\"hi\" && python3 "),
            // A quote in the command itself names something the reader does
            // not model.
            ("", "cd src && python3 'a.py' "),
            ("", "cd 'src' && 'python3' "),
        ] {
            assert_eq!(
                command_start(earlier, before),
                None,
                "{earlier:?} {before:?}"
            );
        }
    }
}
