//! The grammar these pin is the one the retired Python `_perform_read`,
//! `_head_tail`, `_sed`, `_line_count` and the target half of `_resolve_target`
//! enforced, read back argument by argument.

use guard_contracts::{VerifiedReadPlanV1, VerifiedReadSelectionV1};

use crate::verified_read_plan::verified_read_plan;

fn plan(argv: &[&str]) -> Result<VerifiedReadPlanV1, &'static str> {
    let owned: Vec<String> = argv.iter().map(|value| (*value).to_owned()).collect();
    verified_read_plan(&owned)
}

fn error(argv: &[&str]) -> &'static str {
    plan(argv).expect_err("argv should be refused")
}

#[test]
fn bare_pwd_reads_the_working_directory() {
    let plan = plan(&["pwd"]).expect("plan");
    assert_eq!(plan.operation_id, "working-directory");
    assert_eq!(plan.target, None);
    assert_eq!(plan.selection, VerifiedReadSelectionV1::WorkingDirectory {});
}

#[test]
fn pwd_with_an_argument_leaves_the_cohort() {
    assert_eq!(
        error(&["pwd", "-L"]),
        "operation is outside the verified-read cohort"
    );
}

#[test]
fn head_accepts_every_spelling_of_the_bound() {
    for bound in ["-40", "--lines=40", "40"] {
        let plan = plan(&["head", bound, "src/main.py"]).expect("plan");
        assert_eq!(plan.operation_id, "bounded-head");
        assert_eq!(plan.target.as_deref(), Some("src/main.py"));
        assert_eq!(
            plan.selection,
            VerifiedReadSelectionV1::LeadingLines { count: 40 }
        );
    }
}

#[test]
fn tail_selects_from_the_end() {
    let plan = plan(&["tail", "-5", "log.txt"]).expect("plan");
    assert_eq!(plan.operation_id, "bounded-tail");
    assert_eq!(
        plan.selection,
        VerifiedReadSelectionV1::TrailingLines { count: 5 }
    );
}

#[test]
fn the_line_bound_holds_at_a_thousand() {
    assert!(plan(&["head", "-1000", "main.py"]).is_ok());
    assert_eq!(
        error(&["head", "-1001", "main.py"]),
        "line count exceeds the bound"
    );
    assert_eq!(
        error(&["head", "-0", "main.py"]),
        "line count exceeds the bound"
    );
    assert_eq!(
        error(&["head", "-", "main.py"]),
        "line count exceeds the bound"
    );
    assert_eq!(
        error(&["head", "ten", "main.py"]),
        "line count exceeds the bound"
    );
}

#[test]
fn zero_padding_is_read_as_the_number_it_spells() {
    for bound in ["-0000000001", "--lines=0000000040", "000000000000000005"] {
        assert!(plan(&["head", bound, "main.py"]).is_ok(), "{bound}");
    }
    assert_eq!(
        error(&["head", "-00000001001", "main.py"]),
        "line count exceeds the bound"
    );
    assert_eq!(
        error(&["head", "-0000", "main.py"]),
        "line count exceeds the bound"
    );
    assert_eq!(
        error(&["head", "-\u{0664}", "main.py"]),
        "line count exceeds the bound"
    );
    assert_eq!(
        error(&["sed", "-n", "0000003p", "main.py"]),
        "sed expression is outside the verified grammar"
    );
}

#[test]
fn head_and_tail_take_exactly_one_bound_and_one_file() {
    for argv in [
        vec!["head", "-5"],
        vec!["head", "main.py"],
        vec!["head", "-5", "a.py", "b.py"],
        vec!["tail"],
    ] {
        assert_eq!(error(&argv), "head and tail require one bound and one file");
    }
}

#[test]
fn sed_reads_a_single_line_and_a_range() {
    let single = plan(&["sed", "-n", "5p", "main.py"]).expect("plan");
    assert_eq!(single.operation_id, "bounded-source-view");
    assert_eq!(
        single.selection,
        VerifiedReadSelectionV1::LineRange { start: 5, end: 5 }
    );
    let range = plan(&["sed", "-n", "5,9p", "main.py"]).expect("plan");
    assert_eq!(
        range.selection,
        VerifiedReadSelectionV1::LineRange { start: 5, end: 9 }
    );
}

#[test]
fn sed_requires_the_quiet_flag_and_three_arguments() {
    for argv in [
        vec!["sed", "5p", "main.py"],
        vec!["sed", "-i", "5p", "main.py"],
        vec!["sed", "-n", "5p"],
        vec!["sed", "-n", "5p", "a.py", "b.py"],
    ] {
        assert_eq!(
            error(&argv),
            "sed requires one bounded print expression and one file"
        );
    }
}

#[test]
fn sed_expressions_outside_the_grammar_are_refused() {
    for expression in ["5", "5,p", "5,6,7p", "p", "s/a/b/p", "5 p", "1234567p"] {
        assert_eq!(
            error(&["sed", "-n", expression, "main.py"]),
            "sed expression is outside the verified grammar",
            "expression {expression}"
        );
    }
}

#[test]
fn sed_ranges_hold_at_the_bound_and_run_forwards() {
    assert!(plan(&["sed", "-n", "1,1000p", "main.py"]).is_ok());
    for expression in ["0p", "1,1001p", "9,5p"] {
        assert_eq!(
            error(&["sed", "-n", expression, "main.py"]),
            "sed range exceeds the bound",
            "expression {expression}"
        );
    }
}

#[test]
fn the_executable_is_a_bare_name() {
    for name in ["/bin/head", "./head", "../head", "bin/head", "."] {
        assert_eq!(
            error(&[name, "-5", "main.py"]),
            "verified reads do not launch caller-selected executables",
            "name {name}"
        );
    }
    // `PurePath("..").name` is `".."`, so Python lets this one reach the
    // cohort check instead; the read is refused either way.
    assert_eq!(
        error(&["..", "-5", "main.py"]),
        "operation is outside the verified-read cohort"
    );
}

#[test]
fn an_unjoined_command_line_is_not_an_executable() {
    assert_eq!(
        error(&["head -40 main.py"]),
        "operation is outside the verified-read cohort"
    );
}

#[test]
fn argv_must_be_present_and_exact() {
    assert_eq!(error(&[]), "argv must be a non-empty tuple");
    for argv in [
        vec!["head", "", "main.py"],
        vec!["", "-5", "main.py"],
        vec!["head", "-5", "ma\0in.py"],
    ] {
        assert_eq!(error(&argv), "argv must contain exact non-empty strings");
    }
}

#[test]
fn targets_are_static_relative_paths() {
    for target in [
        "/etc/passwd",
        "\\etc\\passwd",
        "\\\\server\\share\\main.py",
        "//server/share/main.py",
        "C:main.py",
        "C:\\Windows\\win.ini",
        "c:/Windows/win.ini",
        "$HOME/main.py",
        "`id`",
        "a<b",
        "a>b",
        "a|b",
        "a;b",
        "a&b",
        "*.py",
        "main.?y",
        "[ab].py",
    ] {
        assert_eq!(
            error(&["head", "-5", target]),
            "target must be a static relative path",
            "target {target}"
        );
    }
}

#[cfg(windows)]
#[test]
fn a_stream_name_is_not_a_relative_path_on_windows() {
    assert_eq!(
        error(&["head", "-5", "main.py:hidden"]),
        "target must be a static relative path"
    );
}

#[test]
fn a_relative_target_keeps_its_spelling_for_the_executor() {
    let plan = plan(&["sed", "-n", "1,2p", "../sibling/main.py"]).expect("plan");
    assert_eq!(plan.target.as_deref(), Some("../sibling/main.py"));
}
