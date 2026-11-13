//! The boundary the bounded `jq` stdin read keeps: which programs are
//! admitted over the value a pipeline already produced, and which of jq's
//! own options may precede them.

use super::{
    jq_filter_position, safe_jq_file_arguments, safe_jq_piped_arguments,
    safe_jq_stdin_arguments,
};

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

/// A program that renders what it read into text is a read: the agent
/// formats the value it already has, and reaches nothing else.
#[test]
fn a_filter_that_renders_the_value_read_into_text_is_admitted() {
    for filter in [
        "\"\\(.type)\"",
        ".[] | \"\\(.type)\\t\\(.name)\"",
        "[.[] | \"\\(.id) \\(.name)\"] | join(\"\\n\")",
    ] {
        let args = arguments(&["-r", filter]);
        assert!(safe_jq_stdin_arguments(&args), "{filter}");
        assert_eq!(jq_filter_position(&args, true), Some(1), "{filter}");
    }
}

/// A bounded range is admitted alone, but the native jq decision refuses a
/// filter that composes per-call range bounds, including calls exposed by
/// bindings or zero-arity definitions.
#[test]
fn composed_range_generators_are_terminally_refused() {
    let bounded = arguments(&["-n", "range(100000)"]);
    assert!(safe_jq_stdin_arguments(&bounded));
    assert_eq!(jq_filter_position(&bounded, true), Some(1));

    for filter in [
        "range(100000) | range(100000)",
        "range(100000) as $x | range(100000)",
        "def inner: range(100000); def outer: inner; outer | range(100000)",
        "def gen: range(100000); gen as $x | range(100000)",
        "range(100000) | map(range(100000))",
    ] {
        let args = arguments(&["-n", filter]);
        assert!(!safe_jq_stdin_arguments(&args), "{filter}");
        assert_eq!(jq_filter_position(&args, true), None, "{filter}");
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
        "reduce .[] as $item (0; env)",
        "limit(1; inputs)",
        "include \"evil\"; .",
    ] {
        let args = arguments(&["-r", filter]);
        assert!(!safe_jq_stdin_arguments(&args), "{filter}");
        assert_eq!(jq_filter_position(&args, true), None, "{filter}");
    }
}

/// Options that only shape parsing and printing are skipped, clustered or
/// spelled out, and so is a binding of a name to a command-line value. With
/// no path context, a binding that reads a file is refused. Every other word
/// is read as the filter, so an option that names a filter file or a module
/// directory has to clear the grammar as a filter and cannot.
#[test]
fn only_read_only_options_are_skipped() {
    for options in [
        vec!["-r"],
        vec!["-rc"],
        vec!["-s", "-S"],
        vec!["--slurp", "--sort-keys"],
        vec!["--raw-output", "--tab"],
        vec!["-n"],
        vec!["--arg", "name", "value"],
        vec!["--argjson", "limit", "3"],
    ] {
        let mut words = options.clone();
        words.push(".items | length");
        assert!(safe_jq_stdin_arguments(&arguments(&words)), "{options:?}");
    }
    for options in [
        vec!["-f", "/tmp/filter.jq"],
        vec!["--from-file", "/tmp/filter.jq"],
        vec!["-L", "/tmp/modules"],
        vec!["--rawfile", "body", "/etc/passwd"],
        vec!["--slurpfile", "rows", "/tmp/rows.json"],
        vec!["-rf"],
        vec!["--args"],
        vec!["--arg", "name"],
        vec!["--arg", "1name", "value"],
        vec!["--argfile", "rows", "/tmp/rows.json"],
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

/// A name `--arg` or `--argjson` binds may be read back, and only that name.
/// `$ENV` and `$__loc__` stay refused even when the command line binds them,
/// since jq answers them from the process and the program text.
#[test]
fn command_line_bindings_bind_only_their_own_names() {
    for words in [
        vec!["--arg", "want", "open", ".[] | select(.state == $want)"],
        vec!["-r", "--argjson", "n", "3", "limit($n; .[])"],
        vec!["--arg", "a", "x", "--arg", "b", "y", "[$a, $b]"],
        vec![
            "--arg",
            "key",
            "x",
            "def pick: select(.name == $key); .[] | pick",
        ],
    ] {
        assert!(safe_jq_stdin_arguments(&arguments(&words)), "{words:?}");
    }
    for words in [
        vec!["--arg", "want", "open", "$other"],
        vec!["--arg", "ENV", "x", "$ENV"],
        vec!["--arg", "__loc__", "x", "$__loc__"],
        vec![".[] | select(.state == $want)"],
    ] {
        assert!(!safe_jq_stdin_arguments(&arguments(&words)), "{words:?}");
    }
    assert!(!safe_jq_stdin_arguments(&arguments(&["$want"])));
}

/// A path-bearing jq binding cannot be proven from the text of the name
/// alone: in an unlocated session it may be a link to a credential. Plain
/// command-line values remain independent of the filesystem context.
#[test]
fn file_bindings_need_a_real_path_context() {
    let context_free = crate::pretool::PathContext::default();
    let file_binding = arguments(&["--slurpfile", "data", "ordinary.json", "."]);
    let value_binding = arguments(&["--arg", "data", "safe", "$data"]);
    assert!(!safe_jq_piped_arguments(&file_binding, context_free));
    assert!(!safe_jq_file_arguments(
        &arguments(&["-n", "--rawfile", "data", "ordinary.json", "."]),
        crate::pretool::PathContext::default(),
    ));
    assert!(safe_jq_piped_arguments(
        &value_binding,
        crate::pretool::PathContext::default(),
    ));
}
