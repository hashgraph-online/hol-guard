//! Line-numbered slices of a source file.
//!
//! Oh My Pi's `read` returns a selected range as `N:content` rows under a
//! `[path#hash]` header, with collapsed regions (`N-M:` rows), omission rows
//! (`…`) and notes. It also anchors the range with the first and last line
//! of the enclosing block, set apart by omission rows. A secret elsewhere in
//! the file is not in such a slice, so when the whole file matches a secret
//! rule the review scans only the lines the slice covers, one run of
//! consecutive lines at a time; the omitted lines between runs are not shown.
//! Every numbered row must equal that line of the current file; stale or
//! invented output keeps the whole-file decision.
//!
//! A rule can match across lines: a credential name, its separator and its
//! value may be split by any run of whitespace, blank lines included. So a
//! slice is blocked when any match the whole-file scan counted overlaps the
//! lines it covers, which keeps its verdict at least as strict as the
//! whole-file one for those lines. The covered lines, with [`CONTEXT_LINES`]
//! above them, are also scanned on their own. A private key body has no
//! marker of its own, so a slice that overlaps a key block keeps the block.

use std::ops::Range;

/// Lines above each run of a slice that are scanned with it.
pub(crate) const CONTEXT_LINES: usize = 3;

/// The runs of consecutive file lines (1-based, inclusive, ascending) a
/// slice covers, when every numbered row matches the file.
pub(crate) fn covered_runs(output: &str, file: &str) -> Option<Vec<(usize, usize)>> {
    let lines: Vec<&str> = file.lines().collect();
    let mut covered: Vec<(usize, usize)> = Vec::new();
    for row in output.lines() {
        let Some((label, content)) = row.split_once(':') else {
            continue;
        };
        if let Some((first, last)) = label.split_once('-') {
            // A collapsed region: the host summarizes lines it does not show.
            let (Some(first), Some(last)) = (line_number(first), line_number(last)) else {
                continue;
            };
            if first > last || last > lines.len() {
                return None;
            }
            covered.push((first, last));
            continue;
        }
        let Some(number) = line_number(label) else {
            continue;
        };
        let line = lines.get(number.checked_sub(1)?)?;
        if !shows(content, line) {
            return None;
        }
        covered.push((number, number));
    }
    covered.sort_unstable();
    let mut runs: Vec<(usize, usize)> = Vec::new();
    for (first, last) in covered {
        match runs.last_mut() {
            Some(run) if first <= run.1 + 1 => run.1 = run.1.max(last),
            _ => runs.push((first, last)),
        }
    }
    (!runs.is_empty()).then_some(runs)
}

/// Whether a private key block overlaps lines `first..=last`.
pub(crate) fn key_block_overlaps(file: &str, first: usize, last: usize) -> bool {
    let mut start = None;
    for (index, line) in file.lines().enumerate() {
        let number = index + 1;
        if start.is_none() && line.contains("-----BEGIN") && line.contains("PRIVATE KEY-----") {
            start = Some(number);
        }
        if let Some(begin) = start {
            if line.contains("-----END") {
                if begin <= last && number >= first {
                    return true;
                }
                start = None;
            }
        }
    }
    // An unterminated block runs to the end of the file.
    start.is_some_and(|begin| begin <= last)
}

/// Whether any of `spans` (byte ranges of `file`) overlaps lines
/// `first..=last` (1-based), line breaks included.
pub(crate) fn spans_overlap(file: &str, first: usize, last: usize, spans: &[Range<usize>]) -> bool {
    let mut start = None;
    let mut end = file.len();
    let mut offset = 0;
    for (index, line) in file.split_inclusive('\n').enumerate() {
        let number = index + 1;
        if number == first {
            start = Some(offset);
        }
        offset += line.len();
        if number == last {
            end = offset;
            break;
        }
    }
    let Some(start) = start else {
        // Lines the file does not have: nothing to show, nothing to trust.
        return true;
    };
    spans
        .iter()
        .any(|span| span.start < end && span.end > start)
}

/// File lines `first..=last` (1-based), joined.
pub(crate) fn lines(file: &str, first: usize, last: usize) -> String {
    file.lines()
        .skip(first.saturating_sub(1))
        .take(last + 1 - first.max(1))
        .collect::<Vec<_>>()
        .join("\n")
}

fn line_number(label: &str) -> Option<usize> {
    if label.is_empty() || !label.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    label.parse().ok().filter(|number| *number > 0)
}

/// A row shows a line when it repeats it, or a prefix of it cut with `…`.
fn shows(content: &str, line: &str) -> bool {
    content == line
        || content
            .strip_suffix('…')
            .is_some_and(|prefix| line.starts_with(prefix))
}

#[cfg(test)]
mod tests {
    use super::*;

    const FILE: &str = "one\ntwo\nthree\nfour\nfive\nsix";

    #[test]
    fn numbered_rows_must_repeat_the_file() {
        assert_eq!(
            covered_runs("[f.sh#AB12]\n2:two\n3:three\n\n[2 more lines]", FILE),
            Some(vec![(2, 3)])
        );
        assert_eq!(covered_runs("4:fo…\n5-6:  { … }", FILE), Some(vec![(4, 6)]));
        for output in [
            "2:tw0",
            "2:two\n3:four",
            "7:seven",
            "0:one",
            "1:on…e",
            "4-9: …",
        ] {
            assert_eq!(covered_runs(output, FILE), None, "{output:?}");
        }
        assert_eq!(covered_runs("[f.sh#AB12]\nno rows", FILE), None);
    }

    #[test]
    fn rows_set_apart_by_omissions_are_separate_runs() {
        // The enclosing block's first and last lines anchor the range.
        assert_eq!(
            covered_runs("1:one\n…\n3:three\n4:four\n…\n6:six", FILE),
            Some(vec![(1, 1), (3, 4), (6, 6)])
        );
        assert_eq!(
            covered_runs("1:one\n…\n6:six", FILE),
            Some(vec![(1, 1), (6, 6)])
        );
        // Adjacent and overlapping rows join one run, in any order.
        assert_eq!(
            covered_runs("5:five\n2:two\n3-4:  …\n4:four", FILE),
            Some(vec![(2, 5)])
        );
    }

    #[test]
    fn key_blocks_overlapping_a_slice_are_found() {
        // Assembled so that repository secret scanning does not flag the fixture.
        let begin = concat!("-----BEGIN ", "PRIVATE KEY-----");
        let file = &format!("a\n{begin}\nbody\nbody\n-----END PRIVATE KEY-----\nb\nc");
        assert!(key_block_overlaps(file, 3, 4));
        assert!(key_block_overlaps(file, 5, 7));
        assert!(!key_block_overlaps(file, 6, 7));
        assert!(!key_block_overlaps(file, 1, 1));
        let open = concat!("a\nb\n-----BEGIN RSA ", "PRIVATE KEY-----\nbody\nbody");
        assert!(key_block_overlaps(open, 5, 5));
        assert!(!key_block_overlaps(open, 1, 2));
    }

    #[test]
    fn spans_overlap_the_lines_they_touch() {
        // Lines start at bytes 0, 4, 8, 14, 19 and 24.
        let span = |start: usize, end: usize| [Range { start, end }];
        assert!(spans_overlap(FILE, 2, 3, &span(0, 5)));
        assert!(spans_overlap(FILE, 2, 3, &span(13, 20)));
        assert!(spans_overlap(FILE, 6, 6, &span(10, 26)));
        assert!(!spans_overlap(FILE, 2, 3, &span(0, 4)));
        assert!(!spans_overlap(FILE, 2, 3, &span(14, 20)));
        assert!(!spans_overlap(FILE, 2, 3, &[]));
        assert!(spans_overlap(FILE, 7, 7, &[]));
    }

    #[test]
    fn lines_are_taken_by_number() {
        assert_eq!(lines(FILE, 2, 3), "two\nthree");
        assert_eq!(lines(FILE, 1, 1), "one");
        assert_eq!(lines(FILE, 5, 9), "five\nsix");
    }
}
