//! An angle bracket the redirect projection left behind is quoted text, not a
//! redirect the shell would act on.
use super::tests::{controls, decision};

const FAILED: &str = "native_command_extension_evaluation_failed";

/// A commit trailer's address, an HTML tag and a comparison all survive the
/// projection inside their quotes, because the projection removes only the
/// redirects the shell acts on. Counting those leftovers as data movement
/// turned an ordinary file write into an evaluation failure, which blocks
/// outright with no approval left to give it.
#[test]
fn a_quoted_angle_bracket_beside_a_redirect_is_not_data_movement() {
    let controls = controls(serde_json::json!([]), false);
    for command in [
        "echo hi > docs/a.md && git commit -q -m \"Fix <tag> handling\"",
        "echo \"<html>\" > docs/index.html",
        "printf '%s\\n' \"a < b\" > docs/note.txt",
        "mkdir -p docs && cat > docs/a.md <<'EOF'\n# Branch audit\nEOF\ngit add docs/a.md && git commit -q -m \"Add branch audit summary\n\nReported-by: Audit Bot <bot@example.invalid>\"",
    ] {
        let (action, reason) = decision(&controls, command);
        assert_ne!(reason, FAILED, "{command}");
        assert_ne!(action, "block", "{command}");
    }
}

/// Only the brackets are set aside. A substitution still reads something the
/// command text does not hold, and a link the redirect could follow still
/// means the literal path is no longer proof of the file it opens. Which
/// proof stops each one is the runtime's business — a sensitive read and an
/// unreadable extension are both a stop — so the test holds the stop itself.
#[test]
fn stripping_the_brackets_keeps_every_other_redirect_proof() {
    let controls = controls(serde_json::json!([]), false);
    for command in [
        "echo \"$(cat secrets.txt)\" > docs/a.md",
        "echo \"`cat secrets.txt`\" > docs/a.md",
        "ln -s /etc/passwd docs/a.md && echo hi > docs/a.md",
    ] {
        let (action, reason) = decision(&controls, command);
        assert_ne!(action, "allow", "{command} ({reason})");
    }
}
