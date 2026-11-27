//! A `cd` operand whose directory name holds `[` or `]` inside quotes.
//!
//! Frameworks name dynamic route folders with brackets, such as
//! `app/items/[slug]`, so agents `cd` into them. Unquoted, `[slug]` is a
//! glob: it matches a one-letter entry named `s`, `l`, `u` or `g`, and with no
//! match the shell either keeps the word or stops, depending on its options.
//! The parser hands over the word without its quotes, so the directory proof
//! refuses every bracket it sees. Inside quotes the shell passes the name
//! through as typed, and the directory it names is the one the proof
//! resolves. This module reads the segment's own text to tell the two apart.

use crate::CommandSegmentV1;

/// The directory a `cd` segment's single operand names, proved as
/// [`super::verified_cwd_target`] proves it, with one more accepted spelling:
/// a name whose brackets the segment's text quotes. A `*`, `?` or backslash
/// still keeps the review, quoted or not.
pub(in crate::pretool) fn verified_segment_cwd_target(
    segment: &CommandSegmentV1,
    target: &str,
    context: super::super::PathContext<'_>,
) -> Option<String> {
    super::verified_cwd_target(target, context).or_else(|| {
        (target.contains(['[', ']']) && brackets_quoted(&segment.text))
            .then(|| super::verified_cwd_target_with(target, context, true))
            .flatten()
    })
}

/// Whether every `[` and `]` in the text sits inside single or double
/// quotes. A backslash-escaped bracket outside quotes counts as unquoted;
/// the escape is rare and the directory proof refuses backslashes anyway.
///
/// An ANSI-C `$'...'` word ends at a different apostrophe than a plain
/// single-quoted one, because a backslash escapes `'` inside it, and a
/// `$"..."` word is translated before use. This scanner models neither, so a
/// segment that holds either keeps its review.
fn brackets_quoted(text: &str) -> bool {
    if text.contains("$'") || text.contains("$\"") {
        return false;
    }
    let mut quote = None;
    let mut escaped = false;
    for character in text.chars() {
        if escaped {
            escaped = false;
            if quote.is_none() && matches!(character, '[' | ']') {
                return false;
            }
            continue;
        }
        match (quote, character) {
            (None | Some('"'), '\\') => escaped = true,
            (None, '\'' | '"') => quote = Some(character),
            (Some(open), _) if open == character => quote = None,
            (None, '[' | ']') => return false,
            _ => {}
        }
    }
    quote.is_none()
}

#[cfg(test)]
mod tests {
    use super::brackets_quoted;

    #[test]
    fn only_quoted_brackets_are_literal() {
        for text in [
            r#"cd "app/items/[slug]/parts""#,
            "cd 'app/items/[slug]'",
            r#"cd app/items/"[slug]""#,
            "cd app/items",
        ] {
            assert!(brackets_quoted(text), "{text}");
        }
        for text in [
            "cd app/items/[slug]",
            r#"cd "app/items/"[slug]"#,
            r"cd app/items/\[slug\]",
            r#"cd "app/items/[slug]"#,
            // `$'a\'b'` is one word, so `[x]` is an unquoted glob class.
            r#"cd $'a\'b'[x]"'""#,
            r#"cd $"app/items/[slug]""#,
        ] {
            assert!(!brackets_quoted(text), "{text}");
        }
    }
}
