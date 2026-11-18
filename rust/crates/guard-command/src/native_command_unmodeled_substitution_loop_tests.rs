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
    // The filter still runs, so an extension owning `awk` still judges it.
    for program in ["echo", "shasum", "awk"] {
        assert!(bounded.programs.contains(program), "{program}: {command}");
    }
    let command = r#"actual=$(shasum -a 256 f | awk -F' ' '{print $1}'); test "$actual" = x"#;
    let bounded = reviewable_substitutions(command).unwrap();
    for program in ["shasum", "test", "awk"] {
        assert!(bounded.programs.contains(program), "{program}: {command}");
    }
}

#[test]
fn an_awk_that_could_run_or_write_anything_stays_refused_in_a_substitution() {
    for command in [
        r#"x=$(awk '{system("rm -rf build")}' f)"#,
        r#"x=$(awk 'BEGIN { "date" | getline d; print d }')"#,
        r#"x=$(awk -f prog.awk f)"#,
        // The shell removes the quoting before awk reads its options.
        r#"echo $(awk '-f' payload.awk)"#,
        r#"echo $(awk "-f" payload.awk)"#,
        r#"echo $(awk \-f payload.awk)"#,
        r#"x=$(awk '{print > "out.txt"}' f)"#,
        r#"x=$(awk '{print | "sh"}' f)"#,
        r#"echo "$(awk '{system("id")}' f)""#,
    ] {
        assert!(bounded_substitutions(command).is_none(), "{command}");
        assert!(reviewable_substitutions(command).is_none(), "{command}");
    }
}

#[test]
fn a_quoted_keyword_is_a_program_receiving_the_assignment() {
    for command in [
        r#""do" x=$(cat f)"#,
        r#"'then' x=$(cat f)"#,
        r#"\else x=$(cat f)"#,
    ] {
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
        "set -eu\nfor file in a.js b.tgz; do\n  path=\"$HOME/Downloads/w/$file\"\n  hash=$(shasum -a 256 \"$path\" | awk '{print $1}')\n  grep -F \"| \\`$file\\` | \\`$hash\\` |\" docs/notes.md >/dev/null\ndone\nprintf 'ok\\n'",
    ] {
        let (action, code) = decision(&controls, command);
        assert_ne!(code, FAILED, "{command}\n{}", diagnose(command));
        assert_ne!(action, "block", "{command}: {code}");
    }
}

/// What each step of the substitution arm answered, for a failure message.
fn diagnose(command: &str) -> String {
    let request = crate::CommandModelRequestV1 {
        command: command.to_owned(),
        dialect: crate::default_dialect(),
        transport: crate::default_transport(),
        extraction_provenance: crate::default_provenance(),
    };
    let Ok(parsed) = crate::parse_command(&request) else {
        return String::from("parse failed");
    };
    let looked = super::substitution::without_escaped_backticks(&super::without_lookups(
        &parsed.normalized_text,
    ));
    let bounded = bounded_substitutions(&looked).map(|found| found.text);
    let kept = reviewable_substitutions(&looked).map(|found| found.text);
    let shape = |text: &Option<String>| {
        text.as_ref().map(|text| {
            (
                super::plain_sequence(text),
                super::interpreter_free(text),
                super::plain_after_heredocs(text),
            )
        })
    };
    format!(
        "reason={:?} confidence={} bounded={:?} kept={:?} looked={looked:?} kept_text={kept:?}",
        parsed.uncertainty_reason,
        parsed.confidence,
        shape(&bounded),
        shape(&kept),
    )
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


#[test]
fn nested_shell_quotes_cannot_hide_real_backticks() {
    use super::substitution::without_escaped_backticks;
    // In both cases Bash executes the unescaped printf substitution.
    // A shallow quote reader must leave it visible to the refusal floor.
    for command in [
        r#"v="$(printf "'")"; echo `printf launched` # '"#,
        r#"echo 
    use super::substitution::without_escaped_backticks;
    assert_eq!(
        without_escaped_backticks(r#"grep -F "\`x\`" f"#),
        r#"grep -F "\xx\x" f"#
    );
    assert_eq!(without_escaped_backticks("echo '`id`'"), "echo 'xidx'");
    // An escaped backslash leaves the backtick after it a substitution.
    assert_eq!(without_escaped_backticks(r"echo \\`id`"), r"echo \\`id`");
    assert_eq!(
        without_escaped_backticks("v=$(cat f); echo `id`"),
        "v=$(cat f); echo `id`"
    );
    let controls = controls(github("enabled", None), false);
    let command = "for f in a; do v=$(cat f); echo \"`$v`\"; done";
    assert_eq!(decision(&controls, command).1, FAILED, "{command}");
}
\''; echo `printf launched` # '"#,
    ] {
        let looked = without_escaped_backticks(command);
        assert!(looked.contains("`printf launched`"), "{command}: {looked}");
        assert!(bounded_substitutions(&looked).is_none(), "{command}");
        assert!(reviewable_substitutions(&looked).is_none(), "{command}");
    }
}

#[test]
fn only_an_escaped_backtick_is_read_as_a_plain_character() {
    use super::substitution::without_escaped_backticks;
    assert_eq!(
        without_escaped_backticks(r#"grep -F "\`x\`" f"#),
        r#"grep -F "\xx\x" f"#
    );
    assert_eq!(without_escaped_backticks("echo '`id`'"), "echo 'xidx'");
    // An escaped backslash leaves the backtick after it a substitution.
    assert_eq!(without_escaped_backticks(r"echo \\`id`"), r"echo \\`id`");
    assert_eq!(
        without_escaped_backticks("v=$(cat f); echo `id`"),
        "v=$(cat f); echo `id`"
    );
    let controls = controls(github("enabled", None), false);
    let command = "for f in a; do v=$(cat f); echo \"`$v`\"; done";
    assert_eq!(decision(&controls, command).1, FAILED, "{command}");
}
