use super::{fd_exec, producer_shape_proven};

fn arguments(text: &str) -> Vec<String> {
    text.split_whitespace().map(str::to_owned).collect()
}

fn shape(text: &str) -> (Vec<String>, bool, Vec<String>, Vec<String>) {
    let words = arguments(text);
    let exec = fd_exec(&words).unwrap_or_else(|| panic!("{text}"));
    (
        exec.shape
            .roots
            .iter()
            .map(|root| (*root).to_owned())
            .collect(),
        exec.shape.regular_files_only,
        exec.shape
            .extensions
            .iter()
            .map(|extension| (*extension).to_owned())
            .collect(),
        exec.child.to_vec(),
    )
}

#[test]
fn a_walk_with_no_path_operand_runs_in_the_working_directory() {
    let (roots, regular_files_only, extensions, child) = shape("-t f -e ts -x cat");
    assert_eq!(roots, ["."]);
    assert!(regular_files_only);
    assert_eq!(extensions, ["ts"]);
    assert_eq!(child, ["cat"]);
}

#[test]
fn the_first_operand_is_the_pattern_and_the_rest_are_roots() {
    // `fd -e ts src -x cat` searches the working directory for names matching
    // `src`; only a second operand names a root.
    assert_eq!(shape("-t f -e ts src -x cat").0, ["."]);
    assert_eq!(shape("-t f -e ts . src -x cat").0, ["src"]);
    assert_eq!(shape("-t f -e ts . src docs -X wc -l").0, ["src", "docs"]);
}

#[test]
fn an_option_value_is_read_from_the_next_word_or_after_the_equals_sign() {
    let (roots, regular_files_only, extensions, child) =
        shape("--type=f --extension=rs --max-depth=3 -X wc -l");
    assert_eq!(roots, ["."]);
    assert!(regular_files_only);
    assert_eq!(extensions, ["rs"]);
    assert_eq!(child, ["wc", "-l"]);
    assert!(shape("--type file --extension rs --max-depth 3 -x wc -l").1);
}

#[test]
fn a_child_without_a_type_test_or_with_a_wider_one_carries_no_regular_file_bound() {
    assert!(!shape("-e ts -x cat").1);
    assert!(!shape("-t d -x ls").1);
    // Several `--type` values are a union, so one directory type widens it.
    assert!(!shape("-t f -t d -x ls").1);
}

#[test]
fn an_unknown_option_keeps_the_uncertain_model() {
    for text in [
        // Options that move the walk, or that this reading does not model.
        "--search-path src -t f -x cat",
        "--base-directory src -t f -x cat",
        "-L -t f -e ts -x cat",
        "--follow -t f -e ts -x cat",
        "-l -t f -x cat",
        "-a -t f -e ts -x cat",
        "--format {} -t f -x cat",
        // Short clusters and glued values are not read as options here.
        "-tf -x cat",
        "-Hx cat",
        "-tfx cat",
        // `--` ends fd's own options, so what follows is not this shape.
        "-- -x cat",
    ] {
        assert!(fd_exec(&arguments(text)).is_none(), "{text}");
    }
}

#[test]
fn only_a_separate_exec_option_with_a_listed_child_is_read() {
    for text in [
        // The child decides nothing here; it still has to be a reader the
        // fan-out proof knows.
        "-t f -e ts -x rm",
        "-t f -e ts -x sed -n 1,20p",
        "-t f -e ts -x sh -c cat",
        "-t f -e ts -x ./script.sh",
        // A placeholder or a terminator means the command that runs is not
        // the child with one operand appended.
        "-t f -e ts -x cat {}",
        "-t f -e ts -x cat ;",
        r"-t f -e ts -x cat \;",
        // A glued child is a spelling this reading does not follow.
        "-t f -e ts --exec=cat",
        // No child at all.
        "-t f -e ts -x",
        // No exec option at all.
        "-t f -e ts",
    ] {
        assert!(fd_exec(&arguments(text)).is_none(), "{text}");
    }
}

#[test]
fn more_roots_than_the_fan_out_bound_are_not_read() {
    let roots = (0..9)
        .map(|index| format!("dir{index}"))
        .collect::<Vec<_>>();
    let text = format!("-t f -e ts . {} -x cat", roots.join(" "));
    assert!(fd_exec(&arguments(&text)).is_none(), "{text}");
}

#[test]
fn a_trailing_stderr_merge_is_not_part_of_the_child() {
    assert_eq!(shape("-t f -e ts -x cat 2>&1").3, ["cat"]);
}

#[test]
fn a_walk_the_shape_proof_refuses_stays_a_nested_command_executor() {
    // The parser stops calling a proven `fd` exec a nested command executor so
    // the fan-out proof can see it. Anything this function refuses never
    // reaches that proof, so it has to keep the uncertain model instead.
    for text in [
        // No `--type f`, so the result may hold a symlink or a directory.
        "-e ts -x cat",
        "-e ts . app-portal -x cat",
        // A type union wider than regular files.
        "-t f -t l -e ts -x cat",
        // A content reader with no extension bound, or one off the list.
        "-t f -x cat",
        "-t f -e env -x cat",
        "-t f -e ts -e env -x cat",
    ] {
        let words = arguments(text);
        let exec = fd_exec(&words).unwrap_or_else(|| panic!("{text}"));
        assert!(!producer_shape_proven(&exec), "{text}");
        assert!(
            crate::parser_executables::is_nested_command_executor("fd", &words),
            "{text}"
        );
    }

    for text in [
        "-t f -e ts -x cat",
        "-t f -e md -e txt . docs -x head",
        // `wc` and `stat` print counts and metadata, so they need no
        // extension bound of their own.
        "-t f -x wc -l",
        "-t f -x stat",
    ] {
        let words = arguments(text);
        let exec = fd_exec(&words).unwrap_or_else(|| panic!("{text}"));
        assert!(producer_shape_proven(&exec), "{text}");
        assert!(
            !crate::parser_executables::is_nested_command_executor("fd", &words),
            "{text}"
        );
    }
}
