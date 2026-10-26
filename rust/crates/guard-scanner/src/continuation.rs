//! Whether the text after a matched credential assignment continues its value.

/// Whether the text right after a matched assignment continues the value as
/// an expression, as in `'mock-' + real_secret` or `"mock-"$REAL`, on its own
/// line or, after a trailing `\` or an operator opening the next line, on the
/// next. The match then holds only a prefix of the value, so its wording
/// proves nothing.
///
/// Text that only closes or annotates the value, such as markup, a colon, or
/// an escaped line break (`\n`) in quoted or serialized text, does not.
pub(crate) fn continues_as_expression(rest: &str) -> bool {
    let mut lines = rest.split('\n').map(|line| line.trim_end_matches('\r'));
    let line = lines.next().unwrap_or_default();
    match line.trim() {
        "\\" => return true,
        "" => {
            let next = lines.find(|next| !next.trim().is_empty());
            return next.is_some_and(continues_previous_line);
        }
        _ => {}
    }
    if let Some(after) = escaped_line_break(line) {
        let next = after
            .split("\\n")
            .map(|segment| segment.trim_end_matches("\\r"))
            .chain(lines)
            .find(|next| !next.trim().is_empty());
        return next.is_some_and(continues_previous_line);
    }
    let mut characters = line.chars();
    match characters.next() {
        None => return false,
        Some('.') => {
            return characters.next().is_some_and(|next| !next.is_whitespace());
        }
        Some('&') => return characters.next() != Some('&'),
        // `/>` closes self-closing markup such as `<Input password="x"/>`.
        Some('/') if characters.next() == Some('>') => return false,
        Some(first) if !first.is_whitespace() => return joins_value(first),
        Some(_) => {}
    }
    let trimmed = line.trim_start();
    if trimmed.starts_with("&&") {
        return false;
    }
    matches!(
        trimmed.chars().next(),
        Some('+' | '.' | '|' | '~' | '%' | '&' | '$' | '"' | '\'')
    )
}

/// Whether a character written directly after a value joins more onto it:
/// a word or `$` substitution (shell concatenation), another quoted string,
/// a shell word character such as `-`, `/`, `@` or `=` that the shell keeps
/// in the same word, or a concatenation or formatting operator.
fn joins_value(character: char) -> bool {
    character.is_alphanumeric()
        || matches!(
            character,
            '_' | '$' | '"' | '\'' | '+' | '%' | '|' | '~' | '&' | '-' | '/' | '@' | '='
        )
}

/// The text after an escaped line break (`\n`, `\r\n` or `\r`) that opens
/// `line`, as in quoted or JSON-serialized documentation.
fn escaped_line_break(line: &str) -> Option<&str> {
    ["\\r\\n", "\\n", "\\r"]
        .iter()
        .find_map(|escape| line.strip_prefix(escape))
}

/// Whether a line continues the previous line's expression: indented, and
/// opening with a spaced `+`, `~`, `%` or `||`, or a `.` member call such as
/// `.concat(`. Unindented lines (diff `+` lines, bullets) and `...` do not,
/// nor does a quote or `$`, which usually starts a new statement or entry.
fn continues_previous_line(line: &str) -> bool {
    let operator = line.trim_start();
    if operator.len() == line.len() {
        return false;
    }
    let mut characters = operator.chars();
    match characters.next() {
        Some('+' | '~' | '%') => characters.next().is_some_and(char::is_whitespace),
        Some('|') => characters.next() == Some('|'),
        Some('.') => characters
            .next()
            .is_some_and(|next| next == '_' || next.is_ascii_alphabetic()),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::continues_as_expression;
    use crate::scan_text;
    use guard_rules::MAX_SCAN_BYTES;

    fn flags_assignment(text: &str) -> bool {
        scan_text(text, false, true, MAX_SCAN_BYTES, None)
            .matches
            .iter()
            .any(|matched| matched.classifier == "credential-assignment")
    }

    #[test]
    fn text_that_closes_a_value_does_not_continue_it() {
        for rest in [
            "\\nSecurity command examples stay inert in docs.\\n",
            "\\r\\nnext line",
            "\\n",
            "</code>",
            "/>",
            "/>\\n",
            ": the value to use",
            "> note",
            "!",
            "?",
            "\\\"",
        ] {
            assert!(!continues_as_expression(rest), "{rest:?}");
        }
    }

    #[test]
    fn text_that_joins_a_value_still_continues_it() {
        for rest in [
            "$REAL_SECRET",
            "'real-tail'",
            "\"real-tail\"",
            "real_tail",
            "+real",
            "%real",
            "|| real",
            "&real",
            "-\"$PROD_SECRET\"",
            "/$PROD_SECRET",
            "@$PROD_HOST",
            "=$PROD_SECRET",
            "\\n  + realTail",
            "\\n\\n  .concat(realTail)",
            "\\n\n  + realTail",
        ] {
            assert!(continues_as_expression(rest), "{rest:?}");
        }
    }

    #[test]
    fn documentation_samples_before_escaped_line_breaks_stay_suppressed() {
        for text in [
            "Review fixture notes: credential = 'fixture-only'\\nSecurity command examples stay inert in docs.\\n",
            "\"password = 'mock-token'\\r\\nnext\"",
            "<code>api_key = 'placeholder-key'</code>",
        ] {
            assert!(!flags_assignment(text), "{text:?}");
        }
    }

    #[test]
    fn real_values_and_joined_prefixes_stay_flagged() {
        for text in [
            "credential = 'fixture-prod-value'\\nmore",
            "password = 'mock-'\\n  + realTail",
            "password = 'mock-'$REAL_SECRET",
            "password = 'mock-'\"real-tail\"",
            "password = 'mock-'-\"$PROD_SECRET\"",
            "password = 'mock'/\"$PROD_SECRET\"",
            "password = 'mock'@\"$PROD_HOST\"",
            "password = 'mock'=\"$PROD_SECRET\"",
        ] {
            assert!(flags_assignment(text), "{text:?}");
        }
    }
}
