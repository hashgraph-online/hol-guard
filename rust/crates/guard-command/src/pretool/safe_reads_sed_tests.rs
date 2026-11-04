//! A `sed -n` region a reader names with a pattern reads like one named
//! with line numbers, and the write, negation and unfinished-delimiter
//! spellings beside it keep their review.

use super::*;

fn arguments(items: &[&str]) -> Vec<String> {
    items.iter().map(|item| (*item).to_owned()).collect()
}

fn reads(items: &[&str]) -> bool {
    let root = env!("CARGO_MANIFEST_DIR");
    let context = super::super::PathContext {
        home_dir: Some(root),
        cwd: Some(root),
        ..Default::default()
    };
    safe_sed_arguments(&arguments(items), false, context)
}

/// The segment proof read a `sed -n` address only as a line number or
/// `$`, so every region a reader named with a pattern left the model and
/// went to review. Where no contained run can rescue it -- a host with no
/// sandbox backend -- that review is what blocks the read outright.
#[test]
fn a_region_named_by_a_pattern_reads_like_one_named_by_line_numbers() {
    assert!(reads(&["-n", "1,20p", "Cargo.toml"]));
    assert!(reads(&["-n", "/export/,/^};/p", "Cargo.toml"]));
    assert!(reads(&["-n", "/timeoutSeconds/p", "Cargo.toml"]));
    assert!(reads(&["-n", "0,/export/p", "Cargo.toml"]));
    assert!(reads(&[
        "-n",
        "/export/,/^  timeoutSeconds: 10,/p",
        "Cargo.toml"
    ]));
    assert!(reads(&["-n", "/export/,$p", "Cargo.toml"]));
    // `/^};/` closes a block in ordinary source: the `;` is the pattern's
    // own, not a second command.
    assert!(reads(&["-n", "/^};/p", "Cargo.toml"]));
    assert!(reads(&["-n", "/export/,/^};/p;40,60p", "Cargo.toml"]));
    assert!(reads(&[
        "-n",
        "-e",
        "/export/p",
        "-e",
        "40,60p",
        "Cargo.toml"
    ]));
}

/// Reading the address changes nothing about what a script may do: only
/// `p` prints, and anything that could write, run or reuse an unseen
/// regex keeps its review.
#[test]
fn a_pattern_address_never_carries_a_write_or_a_second_command() {
    assert!(!reads(&["-n", "/export/w out.txt", "Cargo.toml"]));
    assert!(!reads(&["-n", "/export/,/^};/w outp", "Cargo.toml"]));
    assert!(!reads(&["-n", "/export/p;/export/w outp", "Cargo.toml"]));
    assert!(!reads(&["-n", "/export/e id", "Cargo.toml"]));
    assert!(!reads(&["-n", "/export/r /etc/passwd", "Cargo.toml"]));
    assert!(!reads(&["-n", "/export/!p", "Cargo.toml"]));
    assert!(!reads(&["-n", "//p", "Cargo.toml"]));
    assert!(!reads(&["-n", "\\%export%p", "Cargo.toml"]));
    assert!(!reads(&["-n", "/a/,/b/,/c/p", "Cargo.toml"]));
    assert!(!reads(&["-n", "/export/d", "Cargo.toml"]));
    assert!(!reads(&["-i", "/export/p", "Cargo.toml"]));
    // A statement of digits alone keeps the stricter line rule.
    assert!(!reads(&["-n", "0p", "Cargo.toml"]));
    assert!(!reads(&["-n", "p", "Cargo.toml"]));

    // A `;` inside a pattern belongs to the address, so the program is read
    // whole; a delimiter left open is a program this reading never finished.
    assert!(!reads(&["-n", "/export;p", "Cargo.toml"]));
    assert!(!reads(&["-n", "/export/p;/timeout", "Cargo.toml"]));
    assert!(!reads(&["-n", "/export/p;w /tmp/out/x", "Cargo.toml"]));
}
