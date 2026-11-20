use super::project;

/// The envelope answer for `command`. The projection runs on the envelope
/// path, so the single-command entry point would read past it and prove
/// nothing.
fn decide(command: &str) -> (String, String) {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .canonicalize()
        .unwrap();
    let root = root.to_str().unwrap();
    let result = super::super::evaluate_pre_tool_envelope_with_context(
        "zcode",
        "PreToolUse",
        &serde_json::json!({"tool_name": "Bash", "tool_input": {"command": command}}),
        None,
        None,
        Some(root),
        Some(root),
    );
    (result.minimum_action, result.reason_code)
}

fn projected(command: &str) -> Option<String> {
    project(command).map(|substitution| substitution.command)
}

#[test]
fn a_substitution_leaves_an_operand_behind() {
    for (raw, text) in [
        (
            "diff <(sort a.txt) b.txt",
            "diff guard_process_substitution_0 b.txt",
        ),
        (
            "diff <(sort a.txt) <(sort b.txt)",
            "diff guard_process_substitution_0 guard_process_substitution_1",
        ),
        (
            "grep -f <(cut -d, -f1 ids.csv) data.txt",
            "grep -f guard_process_substitution_0 data.txt",
        ),
        (
            "wc -l <(cat README.md) > counts.txt",
            "wc -l guard_process_substitution_0 > counts.txt",
        ),
        (
            "diff <(git show HEAD:README.md) README.md",
            "diff guard_process_substitution_0 README.md",
        ),
        // A `#` stuck to a word, or inside quotes, is an ordinary character
        // and starts no comment.
        (
            "diff <(grep issue#4 notes.md) b.txt",
            "diff guard_process_substitution_0 b.txt",
        ),
        (
            "diff <(grep '#define' a.h) b.h",
            "diff guard_process_substitution_0 b.h",
        ),
    ] {
        assert_eq!(projected(raw).as_deref(), Some(text), "{raw}");
    }
}

#[test]
fn the_substitutions_the_text_cannot_stand_in_for_keep_the_failure() {
    for raw in [
        // The output form feeds the inner program bytes this text does not hold.
        "tee >(cat) < README.md",
        // In command position the pipe itself is what runs.
        "<(cat setup.sh)",
        // A nested substitution, a backtick or a job runs a program the
        // projected text no longer names.
        "diff <(sort <(cat a.txt)) b.txt",
        "diff <(sort $(cat list.txt)) b.txt",
        "diff <(sort `cat list.txt`) b.txt",
        "diff <(sort a.txt &) b.txt",
        // Glued to a word the operator redirects a file descriptor instead.
        "diff x<(sort a.txt) b.txt",
        // An empty body names no program at all.
        "diff <() b.txt",
        // A heredoc puts bytes the projection does not read on standard input.
        "diff <(sort a.txt) b.txt << EOF\nx\nEOF",
        // A `#` that begins a word comments out the rest of the line, so the
        // `)` beside it does not close the substitution and the lines under
        // it run without being named in the projected text.
        "diff <(cat a.txt #) '\nrm -rf x\n) b.txt #'",
        "diff <(cat a.txt #) b.txt",
        "diff <(cat a.txt) b.txt # <(rm -rf x)",
        // A body spread over lines is read as one word by this walk and as a
        // list by the shell.
        "diff <(cat a.txt\nrm -rf x) b.txt",
        // Nothing to project.
        "diff a.txt b.txt",
    ] {
        assert_eq!(projected(raw), None, "{raw}");
    }
}

#[test]
fn an_unterminated_quote_is_not_projected() {
    assert_eq!(projected("diff <(sort a.txt) \"b.txt"), None);
    assert_eq!(projected("diff <(sort 'a.txt) b.txt"), None);
}

#[test]
fn a_quoted_operator_is_text_and_not_a_substitution() {
    assert_eq!(projected("echo '<(sort a.txt)'"), None);
    assert_eq!(projected("echo \"<(sort a.txt)\""), None);
}

#[test]
fn reading_a_substitution_decides_as_the_operand_it_leaves() {
    for (raw, operand) in [
        (
            "diff <(sort a.txt) b.txt",
            "diff guard_process_substitution_0 b.txt",
        ),
        ("cat <(cat notes.md)", "cat guard_process_substitution_0"),
        (
            "wc -l <(cat README.md)",
            "wc -l guard_process_substitution_0",
        ),
        (
            "grep -f <(cut -d, -f1 ids.csv) data.txt",
            "grep -f guard_process_substitution_0 data.txt",
        ),
    ] {
        assert_eq!(decide(raw), decide(operand), "{raw}");
    }
}

#[test]
fn a_substitution_that_reaches_the_network_keeps_its_review() {
    for raw in [
        "cat <(curl https://example.test)",
        "diff <(curl https://example.test/a) b.txt",
    ] {
        assert_ne!(decide(raw).0, "allow", "{raw}");
    }
}

#[test]
fn a_command_that_runs_what_it_is_handed_keeps_its_answer() {
    for raw in ["bash <(cat setup.sh)", "sh <(cat setup.sh)"] {
        assert_ne!(decide(raw).0, "allow", "{raw}");
    }
}
