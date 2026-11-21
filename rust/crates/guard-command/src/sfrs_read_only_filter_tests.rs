//! Grep operand-classification and attached-redirection coverage for the
//! read-only lookup filters, ported from the retired Python
//! `read_only_filters` regression tests. The recorded operand vectors replay
//! real command text and do not carry these adversarial option shapes.

use crate::sfrs_read_only_filters::split_attached_redirection_token;
use crate::sfrs_search_filters::read_only_lookup_filter_grep_args_are_safe;

fn safe(values: &[&str]) -> bool {
    let args: Vec<String> = values.iter().map(|value| (*value).to_owned()).collect();
    read_only_lookup_filter_grep_args_are_safe(&args, None)
}

#[test]
fn grep_filter_treats_the_first_positional_as_the_pattern() {
    // A lone URI argument is the pattern, never a file operand.
    assert!(safe(&["http://127.0.0.1:5497/requests/abc#token=secret"]));
    assert!(safe(&["skill://guard-dev-testing"]));
    // Likewise a lone sensitive-looking path: grep matches it as a literal.
    assert!(safe(&[".env"]));
    assert!(!safe(&[]));
}

#[test]
fn grep_filter_validates_trailing_file_operands() {
    assert!(safe(&["pattern", "src/main.py"]));
    assert!(safe(&["pattern", "src/main.py", "src/utils.py"]));
    assert!(!safe(&["pattern", "src/main.py", ".env"]));
    assert!(!safe(&["pattern", ".env"]));
    // `http:` can be a symlink to `.`, so `http://.env` reads `./.env`.
    assert!(!safe(&["pattern", "http://.env"]));
    assert!(!safe(&["pattern", ">", "/etc/passwd"]));
}

#[test]
fn grep_filter_validates_pattern_file_options() {
    assert!(!safe(&["-f", ".env", "pattern"]));
    assert!(safe(&["-f", "src/patterns.txt", "src/data.py"]));
    assert!(!safe(&["--file", ".env"]));
    assert!(safe(&["-fsrc/patterns.txt"]));
    assert!(!safe(&["-f.env"]));
    assert!(!safe(&["--file=.env"]));
    assert!(!safe(&["--exclude-from", ".env"]));
    assert!(!safe(&["--exclude-from=.env"]));
    assert!(safe(&[
        "--exclude-from",
        "src/patterns.txt",
        "pattern",
        "src/main.py"
    ]));
}

#[test]
fn grep_filter_counts_a_pattern_file_as_the_pattern() {
    // Once -f supplies the pattern, the next positional is a file operand.
    // The pattern file itself is allowed, so only that operand can refuse.
    assert!(safe(&["-f", "src/patterns.txt", "src/main.py"]));
    assert!(!safe(&["-f", "src/patterns.txt", ".env"]));
    assert!(!safe(&["-fsrc/patterns.txt", ".env"]));
    assert!(!safe(&["-f", "src/patterns.txt", "/etc/passwd"]));
    assert!(!safe(&["--file=src/patterns.txt", ".env"]));
    assert!(!safe(&["-nf", "src/patterns.txt", ".env"]));
}

#[test]
fn grep_filter_does_not_validate_pattern_options_as_paths() {
    assert!(safe(&["-e", "http://example.com"]));
    assert!(safe(&["-ehttp://example.com"]));
    assert!(safe(&["--regexp=http://example.com"]));
    assert!(safe(&["-in", "http://example.com"]));
}

#[test]
fn grep_filter_matches_long_options_whole_not_by_letter() {
    assert!(safe(&["--fixed-strings", "pattern", "src/main.py"]));
    assert!(safe(&["--extended-regexp", "pattern", "src/main.py"]));
}

#[test]
fn grep_filter_handles_context_values_and_the_option_terminator() {
    assert!(safe(&["-A", "3", "pattern", "src/main.py"]));
    assert!(!safe(&["-C", "2", "pattern", ".env"]));
    assert!(safe(&["--", "pattern", "src/main.py"]));
    assert!(!safe(&["--", "pattern", ".env"]));
}

#[test]
fn grep_filter_rejects_dangling_value_options() {
    assert!(!safe(&["-f"]));
    assert!(!safe(&["-e"]));
}

#[test]
fn split_attached_redirection_token_handles_long_text_without_backtracking() {
    let token = format!("{}>danger.txt", "!".repeat(20_000));
    assert_eq!(
        split_attached_redirection_token(&token),
        Some((
            "!".repeat(20_000),
            String::new(),
            ">".to_owned(),
            "danger.txt".to_owned()
        )),
    );
}
