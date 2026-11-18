//! A plain `awk` inside a substitution, and a loop or conditional that keeps
//! a substitution's value, reach the same review card as the text without
//! them instead of an evaluation failure that leaves no approval to give.
use super::substitution::{bounded_substitutions, reviewable_substitutions};
use super::tests::{controls, decision, github};

const FAILED: &str = "native_command_extension_evaluation_failed";

#[test]
fn a_plain_awk_inside_a_substitution_reads_like_one_outside() {
    let command = r#"echo "$(shasum -a 256 f | awk '{print $1}')""#;
    let bounded = bounded_substitutions(command).unwrap();
    for program in ["echo", "shasum"] {
        assert!(bounded.programs.contains(program), "{program}: {command}");
    }
    let command = r#"actual=$(shasum -a 256 f | awk -F' ' '{print $1}'); test "$actual" = x"#;
    let bounded = reviewable_substitutions(command).unwrap();
    for program in ["shasum", "test"] {
        assert!(bounded.programs.contains(program), "{program}: {command}");
    }
}

#[test]
fn an_awk_that_could_run_or_write_anything_stays_refused_in_a_substitution() {
    for command in [
        r#"x=$(awk '{system("rm -rf build")}' f)"#,
        r#"x=$(awk 'BEGIN { "date" | getline d; print d }')"#,
        r#"x=$(awk -f prog.awk f)"#,
        r#"x=$(awk '{print > "out.txt"}' f)"#,
        r#"x=$(awk '{print | "sh"}' f)"#,
        r#"echo "$(awk '{system("id")}' f)""#,
    ] {
        assert!(bounded_substitutions(command).is_none(), "{command}");
        assert!(reviewable_substitutions(command).is_none(), "{command}");
    }
}

#[test]
fn a_loop_that_keeps_a_value_and_runs_no_interpreter_reaches_review() {
    let controls = controls(github("enabled", None), false);
    for command in [
        r#"actual=$(shasum -a 256 f | awk '{print $1}'); test "$actual" = x"#,
        r#"for e in a b; do sum=$(shasum -a 256 "$e" | awk '{print $1}'); test "$sum" = x; done"#,
        r#"for e in a; do a=$(echo x); done"#,
        r#"while read -r f; do n=$(printf '%s' "$f" | wc -c); echo "$f $n"; done < /dev/null"#,
        r#"if [ -f VERSION ]; then v=$(cat VERSION); printf '%s\n' "$v"; fi"#,
        "set -e\nfor entry in 'a 1' 'b 2'; do\n  set -- $entry\n  actual=$(shasum -a 256 \"$1\" | awk '{print $1}')\n  test \"$actual\" = \"$2\"\ndone",
    ] {
        let (action, code) = decision(&controls, command);
        assert_ne!(code, FAILED, "{command}");
        assert_ne!(action, "block", "{command}: {code}");
    }
}

#[test]
fn a_loop_that_hands_a_kept_value_to_an_interpreter_keeps_the_failure() {
    let controls = controls(github("enabled", None), false);
    for command in [
        r#"for f in a; do v=$(cat f); bash -c "$v"; done"#,
        r#"for f in a; do v=$(cat f); eval "$v"; done"#,
        r#"for f in a; do v=$(cat f); node -e "$v"; done"#,
        r#"if true; then v=$(cat f); . ./x.sh; fi"#,
        r#"for f in a; do v=$(cat f); trap "$v" EXIT; done"#,
    ] {
        assert_eq!(decision(&controls, command).1, FAILED, "{command}");
    }
}
