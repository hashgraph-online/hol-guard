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
    assert!(!reads(&["-n", "//p", "Cargo.toml"]));
    assert!(!reads(&["-n", "\\%export%p", "Cargo.toml"]));
    assert!(!reads(&["-n", "/a/,/b/,/c/p", "Cargo.toml"]));
    assert!(!reads(&["-i", "/export/p", "Cargo.toml"]));
    // Line 0 names no line.
    assert!(!reads(&["-n", "0p", "Cargo.toml"]));

    // A `;` inside a pattern belongs to the address, so the program is read
    // whole; a delimiter left open is a program this reading never finished.
    assert!(!reads(&["-n", "/export;p", "Cargo.toml"]));
    assert!(!reads(&["-n", "/export/p;/timeout", "Cargo.toml"]));
    assert!(!reads(&["-n", "/export/p;w /tmp/out/x", "Cargo.toml"]));
}

/// Trimming a listing spells more than a print or a substitution: `1d;$d`
/// drops a header and footer, `/^#/d` drops comments, `5q` stops early and
/// `12s/a/b/` rewrites one line. Each only prints, drops or rewrites lines of
/// the file it reads, so it reads like the print does.
#[test]
fn a_line_delete_quit_or_addressed_substitution_reads_like_a_print() {
    for program in [
        "1d",
        "$d",
        "1d;$d",
        "/^#/d",
        "/^$/d",
        "2,4d",
        "2,4!d",
        "5q",
        "3Q",
        "12s/foo/bar/",
        "/^use /s/foo/bar/g",
        "1,/^}/s/a/b/",
        "0,/export/s/a/b/",
        "1d; s/a/b/; $d",
        "/[0-9]/d",
        "=",
    ] {
        assert!(reads(&[program, "Cargo.toml"]), "{program}");
    }
    assert!(reads(&["-n", "/export/d", "Cargo.toml"]));
    assert!(reads(&["-n", "/export/!p", "Cargo.toml"]));
    assert!(reads(&["-n", "p", "Cargo.toml"]));
    assert!(reads(&["-e", "1d", "-e", "$d", "Cargo.toml"]));
    assert!(reads(&["-E", "/^[[:space:]]*$/d", "Cargo.toml"]));
}

/// The stream reading admits no command that reaches past the stream, no
/// block, label, branch, hold-space or text command, and no in-place edit.
#[test]
fn a_stream_edit_never_writes_reads_or_runs() {
    for program in [
        "1d;w out.txt",
        "1d;r /etc/hosts",
        "1d;R /etc/hosts",
        "1d;W out.txt",
        "1d;e id",
        "12s/a/b/w out.txt",
        "12s/a/b/e",
        "1!G;h;$!d",
        "/^$/N;/\\n$/D",
        "/x/{d}",
        ":a;N;ba",
        "1i hello",
        "$a footer",
        "2c text",
        "y/abc/xyz/",
        "1l",
        "0d",
        "1,0d",
        "//d",
        "/a[/]/d",
        "/a/,+3d",
        "1d 2d",
        "dw out.txt",
        "qw",
        "",
    ] {
        assert!(!reads(&[program, "Cargo.toml"]), "{program}");
    }
    assert!(!reads(&["-i", "1d", "Cargo.toml"]));
    assert!(!reads(&["-i", "", "1d", "Cargo.toml"]));
    assert!(!reads(&["1d", "Cargo.toml", "-i"]));
    assert!(!reads(&["-f", "script.sed", "Cargo.toml"]));
}
