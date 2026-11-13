use super::*;

fn names_only(command: &str) -> bool {
    printenv_renders_only_names(command)
}

#[test]
fn a_dump_piped_into_a_name_filter_renders_no_value() {
    for command in [
        "printenv | grep -oE '^(ALPHAHOST|BETAHOST)[A-Z_]*'",
        "printenv | grep -o -E '^ALPHAHOST[A-Z_]*'",
        "printenv | grep -o --extended-regexp '^ALPHAHOST[A-Z_]*'",
        "printenv | grep -oE -e '^ALPHAHOST[A-Z_]*'",
        "printenv | grep -oE '^ALPHAHOST[A-Z_]*' | sort -u | head -20",
        "printenv | grep -oE '^ALPHAHOST[A-Z_]*' | wc -l",
    ] {
        assert!(names_only(command), "{command}");
    }
}

/// `printenv` ends each variable with a newline, and a value may hold a
/// newline of its own. Every line after the first then carries value bytes
/// and no `=` at all, so a filter that keeps "the text before the `=`" keeps
/// the whole of such a line. `cut` and `awk` cannot prove otherwise, whatever
/// field they are asked for, so neither is accepted here.
#[test]
fn a_filter_that_keeps_the_text_before_the_separator_is_refused() {
    for command in [
        "printenv | cut -d= -f1",
        "printenv | cut -d = -f 1",
        "printenv | cut --delimiter== --fields=1",
        "printenv | cut -s -d= -f1",
        "printenv | awk -F= '{print $1}'",
        "printenv | awk -F '=' '{ print $1 }'",
        "printenv | cut -d= -f1 | sort",
    ] {
        assert!(!names_only(command), "{command}");
    }
}

#[test]
fn a_stage_that_could_render_a_value_keeps_the_review() {
    for command in [
        // no filter at all
        "printenv",
        "printenv | sort | head",
        "printenv | grep x",
        // the match can leave the name
        "printenv | grep -oE 'TOKEN'",
        "printenv | grep -oE '^.*'",
        "printenv | grep -oE '^[^=]*'",
        "printenv | grep -E '^ALPHAHOST[A-Z_]*'",
        "printenv | grep -oE '^[0-A]*'",
        // a match that may read lower case can follow a value line of a key
        "printenv | grep -oE '^M[A-Za-z0-9]*'",
        "printenv | grep -oiE '^alphahost[a-z_]*'",
        "printenv | grep -oi '^ALPHAHOST[A-Z_]*'",
        "printenv | grep -oE '^alphahost[A-Z_]*'",
        // the match need not begin where the pattern is anchored
        "printenv | grep -o '^[A-Za-z_]*'",
        "printenv | grep -oE '^ALPHA|[A-Za-z0-9_]+'",
        "printenv | grep -oE '^ALPHA|S[A-Za-z0-9_]+'",
        "printenv | grep -oE '^(ALPHA|[A-Za-z0-9_]+)'",
        "printenv | grep -oE '^[A-Z]?ALPHA'",
        // the pattern is not one this proof can read
        "printenv | grep -oE '^ALPHA(HOST'",
        "printenv | grep -oE '^ALPHA)'",
        "printenv | grep -oE '^ALPHA' -f patterns.txt",
        "printenv | grep -oE '^ALPHA' extra.txt",
        "printenv | grep -oE -e '^ALPHA' -e '^BETA'",
        "printenv | grep -orE '^ALPHA[A-Z_]*' .",
        // a quote left inside the argument means the shell saw something else
        "printenv | grep -oE \"'^ALPHA'[A-Z_]*\"",
        // a later stage that could name a file or run a program
        "printenv | grep -oE '^ALPHA[A-Z_]*' | sort -o /tmp/names",
        "printenv | grep -oE '^ALPHA[A-Z_]*' | sort --compress-program=sh",
        "printenv | grep -oE '^ALPHA[A-Z_]*' | sort --files0-from=list",
        "printenv | grep -oE '^ALPHA[A-Z_]*' | head -n names.txt",
        "printenv | grep -oE '^ALPHA[A-Z_]*' | cat secrets.txt",
        "printenv | grep -oE '^ALPHA[A-Z_]*' | nl secrets.txt",
        // the dump reaches somewhere else first
        "printenv > /tmp/env.txt",
        "printenv | tee all.txt | grep -oE '^ALPHA[A-Z_]*'",
        "printenv ; grep -oE '^ALPHA[A-Z_]*'",
        // a named dump is not a bare one
        "printenv PATH | grep -oE '^ALPHA[A-Z_]*'",
        // the stage names a program this proof never read
        "printenv | /tmp/grep -oE '^ALPHA[A-Z_]*'",
        "printenv | GREP_OPTIONS=-r grep -oE '^ALPHA[A-Z_]*'",
    ] {
        assert!(!names_only(command), "{command}");
    }
}

/// A match has to begin where the anchor puts it and with a character the
/// pattern spells out. ERE binds `|` loosest, so a top-level alternation
/// anchors only its first alternative and is refused outright; inside a group
/// every alternative is anchored, and each still has to be literal-led,
/// because one that may start with a bracket expression matches a run of
/// value bytes on a line that carries no name at all.
#[test]
fn a_pattern_whose_match_can_start_anywhere_is_refused() {
    assert!(pattern_matches_inside_a_name("^ALPHA[A-Z_]*"));
    assert!(pattern_matches_inside_a_name("^(ALPHA|BETA)[A-Z0-9_]+"));
    assert!(pattern_matches_inside_a_name("^A+[A-Z_]*"));
    assert!(!pattern_matches_inside_a_name("^A|[A-Za-z0-9_]+"));
    assert!(!pattern_matches_inside_a_name("^ALPHA|BETA"));
    assert!(!pattern_matches_inside_a_name("^ALPHA|S[A-Za-z0-9_]+"));
    assert!(!pattern_matches_inside_a_name("^(A|[A-Za-z0-9_]+)"));
    assert!(!pattern_matches_inside_a_name("^[A-Z_]*"));
    assert!(!pattern_matches_inside_a_name("^A*B"));
    assert!(!pattern_matches_inside_a_name("^A?B"));
}

#[test]
fn a_bracket_expression_that_spans_the_separator_is_refused() {
    assert!(!pattern_matches_inside_a_name("A[A-Z_]*"));
    assert!(!pattern_matches_inside_a_name("^A[^Z]*"));
    assert!(!pattern_matches_inside_a_name("^A[0-A]*"));
    assert!(!pattern_matches_inside_a_name("^A[A-z]*"));
    assert!(!pattern_matches_inside_a_name("^A[a-z0-9_]*"));
    assert!(!pattern_matches_inside_a_name("^M[A-Za-z0-9]*"));
    assert!(!pattern_matches_inside_a_name("^a[A-Z]*"));
    assert!(!pattern_matches_inside_a_name("^A\\w*"));
    assert!(!pattern_matches_inside_a_name("^A[A-Z"));
    assert!(!pattern_matches_inside_a_name("^"));
}

/// A token still carrying a quote was not the token the shell passed, so the
/// proof refuses to read it. `-é` is three bytes and two characters, which
/// an option split that counts bytes would cut through the middle of.
#[test]
fn an_argument_this_proof_cannot_read_is_refused() {
    assert_eq!(unquoted("'^A'"), Some("^A".to_owned()));
    assert_eq!(unquoted("\"^A\""), Some("^A".to_owned()));
    assert_eq!(unquoted("^A"), Some("^A".to_owned()));
    assert_eq!(unquoted("'^A'B'"), None);
    assert_eq!(unquoted("-F'='"), None);
    assert!(!stage_renders_only_variable_names(
        "grep",
        &["-é".to_owned(), "^A".to_owned()]
    ));
    assert!(!stage_only_reorders_lines("sort", &["-é".to_owned()]));
}

#[test]
fn a_trailing_stage_may_only_reorder_count_or_trim() {
    for (command, arguments) in [
        ("sort", vec!["-u"]),
        ("sort", vec!["--unique", "--reverse"]),
        ("uniq", vec!["-c"]),
        ("wc", vec!["-l"]),
        ("head", vec!["-n", "20"]),
        ("head", vec!["-n20"]),
        ("head", vec!["--lines=20"]),
        ("tail", vec!["-5"]),
        ("nl", vec![]),
        ("cat", vec!["-n"]),
    ] {
        let arguments: Vec<String> = arguments.iter().map(|a| (*a).to_owned()).collect();
        assert!(
            stage_only_reorders_lines(command, &arguments),
            "{command} {arguments:?}"
        );
    }
    for (command, arguments) in [
        ("sort", vec!["-o", "/tmp/names"]),
        ("sort", vec!["-o/tmp/names"]),
        ("sort", vec!["--output=/tmp/names"]),
        ("sort", vec!["--compress-program=sh"]),
        ("sort", vec!["--files0-from=list"]),
        ("sort", vec!["--random-source=/dev/urandom"]),
        ("sort", vec!["-T", "/tmp"]),
        ("sort", vec!["names.txt"]),
        ("head", vec!["-n", "names.txt"]),
        ("head", vec!["names.txt"]),
        ("nl", vec!["names.txt"]),
        ("cat", vec!["secrets.txt"]),
        ("tee", vec!["-a"]),
        ("xargs", vec!["-n1"]),
    ] {
        let arguments: Vec<String> = arguments.iter().map(|a| (*a).to_owned()).collect();
        assert!(
            !stage_only_reorders_lines(command, &arguments),
            "{command} {arguments:?}"
        );
    }
}
