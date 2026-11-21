//! A quoted word before a heredoc's command no longer blocks the command
//! outright: `cd 'my dir' && python3 - <<'EOF'` reaches the same floor as the
//! unquoted spelling.
use super::tests::{controls, decision};

const FAILED: &str = "native_command_extension_evaluation_failed";

#[test]
fn a_quoted_cd_before_a_heredoc_python_edit_is_not_blocked() {
    let controls = controls(serde_json::json!([]), false);
    let body = "p='src/a.py'\ns=open(p).read()\nopen(p,'w').write(s.replace('a','b'))";
    for lead in [
        "cd 'src' && ",
        "cd \"src\" && ",
        "cd 'my dir'; ",
        "echo 'step 1' && ",
    ] {
        for python in ["python3", "python3 -"] {
            let command = format!("{lead}{python} <<'EOF'\n{body}\nEOF");
            let (action, code) = decision(&controls, &command);
            assert_ne!(code, FAILED, "{command}");
            assert_ne!(action, "block", "{command}: {code}");
        }
    }
}

#[test]
fn a_quoted_lead_keeps_the_failure_for_what_it_always_failed() {
    let controls = controls(serde_json::json!([]), false);
    for command in [
        // A body that can start a program.
        "cd 'src' && python3 - <<'EOF'\nimport os\nos.system('gh pr list')\nEOF",
        // A shell reading its program from the heredoc.
        "cd 'src' && sh <<'EOF'\ngh pr view 12\nEOF",
    ] {
        assert_eq!(decision(&controls, command).1, FAILED, "{command}");
    }
}
