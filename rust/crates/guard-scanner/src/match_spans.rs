//! Where in a text the matches behind a [`scan_text`](crate::scan_text)
//! verdict sit.
//!
//! A rule can match across lines (a credential name, a separator and its
//! value may be separated by any whitespace), so a caller that reviews part
//! of a text needs the byte ranges of the matches the whole-text scan counted.

use super::{counted_matches, PATTERNS};
use std::ops::Range;
use std::time::Instant;

/// The byte ranges of the matches a single-chunk [`scan_text`](crate::scan_text)
/// of `text` counts: the same rules, sample suppression and passes, but every
/// match instead of the first per rule. Returns `None` when `deadline` passes.
pub fn scan_match_spans(
    text: &str,
    local_content: bool,
    source_context: bool,
    deadline: Option<Instant>,
) -> Option<Vec<Range<usize>>> {
    let spans = spans_of(text, true, !local_content, deadline)?;
    if spans.is_empty() && local_content {
        return spans_of(text, false, source_context, deadline);
    }
    Some(spans)
}

fn spans_of(
    text: &str,
    suppress_samples: bool,
    documentation_sample_context: bool,
    deadline: Option<Instant>,
) -> Option<Vec<Range<usize>>> {
    let mut spans = Vec::new();
    for index in 0..PATTERNS.len() {
        if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            return None;
        }
        spans.extend(
            counted_matches(index, text, suppress_samples, documentation_sample_context)
                .map(|matched| matched.range()),
        );
    }
    Some(spans)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan_text;
    use guard_rules::MAX_SCAN_BYTES;

    fn value() -> String {
        ["s3cr3t", "Value", "1234"].concat()
    }

    #[test]
    fn spans_cover_a_value_below_its_name() {
        let value = value();
        for separator in ["api_key =\n\n\n\n\n", "api_key\n\n\n\n=\n\n\n\n"] {
            let text = format!("first()\n{separator}\"{value}\"\nlast()\n");
            let spans = scan_match_spans(&text, false, true, None).unwrap();
            let at = text.find(&value).unwrap();
            assert!(
                spans.iter().any(|span| span.contains(&at)),
                "{separator:?} {spans:?}"
            );
            assert!(spans
                .iter()
                .all(|span| !span.contains(&text.find("last").unwrap())));
        }
    }

    #[test]
    fn spans_agree_with_the_scan_verdict() {
        let value = value();
        let token = format!("{}{}", ["gh", "p_"].concat(), "a".repeat(30));
        let texts = [
            "print(1)\n".to_string(),
            format!("api_key =\n\n\n\n\n\"{value}\"\n"),
            format!("token = '{token}'\n"),
            format!("password = '{}'\n", ["example", "-value-123"].concat()),
            "auth_token = get_secret(\"name\")\n".to_string(),
        ];
        for text in &texts {
            for local in [false, true] {
                let scan = scan_text(text, local, true, MAX_SCAN_BYTES, None);
                let spans = scan_match_spans(text, local, true, None).unwrap();
                assert_eq!(
                    scan.matches.is_empty(),
                    spans.is_empty(),
                    "{text:?} {local}"
                );
            }
        }
    }
}
