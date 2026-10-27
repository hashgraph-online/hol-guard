//! The boundary the bounded `jq` stdin read keeps: which programs are
//! admitted over the value a pipeline already produced, and which of jq's
//! own options may precede them.

use super::{jq_filter_position, safe_jq_stdin_arguments};

fn arguments(words: &[&str]) -> Vec<String> {
    words.iter().map(|word| (*word).to_owned()).collect()
}

/// A filter that reshapes the value read is admitted wherever it sits in
/// the program. `length` and `map(.name)` reach no further than `.items`
/// does, so requiring a leading `.` only refused the spelling, not the
/// capability.
#[test]
fn a_filter_need_not_open_with_a_projection() {
    for filter in [
        "keys",
        "length",
        "{tests: .tests, total: .total}",
        "map(.name)",
        "select(.draft == false)",
        "[.[] | .number]",
    ] {
        let args = arguments(&["-r", filter]);
        assert!(safe_jq_stdin_arguments(&args), "{filter}");
        assert_eq!(jq_filter_position(&args, true), Some(1), "{filter}");
    }
}

/// The grammar, not the leading character, is the gate: a program that
/// reaches the environment, another file or a module is refused however
/// it opens.
#[test]
fn a_filter_that_reaches_outside_the_value_read_is_still_refused() {
    for filter in [
        "$ENV.GH_TOKEN",
        "env",
        "input",
        "input_filename",
        ".items | @sh",
        "reduce .[] as $item (0; . + $item)",
        "limit(1; .[])",
        "include \"evil\"; .",
    ] {
        let args = arguments(&["-r", filter]);
        assert!(!safe_jq_stdin_arguments(&args), "{filter}");
        assert_eq!(jq_filter_position(&args, true), None, "{filter}");
    }
}

/// Options that only shape parsing and printing are skipped, clustered or
/// spelled out. Every other word is read as the filter, so an option that
/// names a file, a module directory or a variable binding has to clear the
/// grammar as a filter and cannot.
#[test]
fn only_read_only_options_are_skipped() {
    for options in [
        vec!["-r"],
        vec!["-rc"],
        vec!["-s", "-S"],
        vec!["--slurp", "--sort-keys"],
        vec!["--raw-output", "--tab"],
        vec!["-n"],
    ] {
        let mut words = options.clone();
        words.push(".items | length");
        assert!(safe_jq_stdin_arguments(&arguments(&words)), "{options:?}");
    }
    for options in [
        vec!["-f", "/tmp/filter.jq"],
        vec!["--from-file", "/tmp/filter.jq"],
        vec!["-L", "/tmp/modules"],
        vec!["--arg", "name", "value"],
        vec!["--rawfile", "body", "/etc/passwd"],
        vec!["--slurpfile", "rows", "/tmp/rows.json"],
        vec!["-rf"],
        vec!["--args"],
        vec!["-"],
    ] {
        let mut words = options.clone();
        words.push(".items | length");
        assert!(!safe_jq_stdin_arguments(&arguments(&words)), "{options:?}");
    }
}

/// Two filters are two programs, and the second would be read as the one
/// proven. A filter still has to be there at all.
#[test]
fn a_second_filter_or_no_filter_is_refused() {
    assert!(!safe_jq_stdin_arguments(&arguments(&[".a", ".b"])));
    assert!(!safe_jq_stdin_arguments(&arguments(&["-r"])));
    assert!(!safe_jq_stdin_arguments(&arguments(&[])));
}
