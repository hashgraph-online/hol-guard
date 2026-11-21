#![cfg(unix)]

use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use serde_json::json;

fn fixture() -> (std::path::PathBuf, std::path::PathBuf) {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/bare-assignment-fixtures")
        .join(format!("fixture-{}-{nonce}", std::process::id()));
    std::fs::create_dir_all(root.join("project")).unwrap();
    let root = std::fs::canonicalize(root).unwrap();
    let project = root.join("project");
    std::fs::write(project.join("one.txt"), "ordinary fixture\n").unwrap();
    std::fs::write(project.join(".env"), "SYNTHETIC_ONLY=fixture\n").unwrap();
    (root, project)
}

fn evaluate(root: &std::path::Path, project: &std::path::Path, command: &str) -> String {
    evaluate_pre_tool_envelope_with_context(
        "zcode",
        "PreToolUse",
        &json!({"tool_name":"bash", "tool_input":{"command":command}}),
        None,
        None,
        root.to_str(),
        project.to_str(),
    )
    .minimum_action
}

/// A list item that only binds a shell variable runs no program, so it cannot
/// make the work around it reviewable. The paired spellings must reach the same
/// decision: naming the operand first is the same read.
#[test]
fn a_literal_binding_decides_as_the_command_without_it() {
    let (root, project) = fixture();
    for (plain, bound) in [
        ("ls .", "R=.; ls $R"),
        ("ls .", "R=.; ls ${R}"),
        ("ls .", "LC_ALL=C; ls ."),
        ("cat one.txt", "R=one.txt; cat $R"),
        ("cat one.txt", "R=. && cat $R/one.txt"),
    ] {
        let expected = evaluate(&root, &project, plain);
        assert_eq!(
            expected, "allow",
            "fixture no longer proves the plain form: {plain}"
        );
        assert_eq!(
            evaluate(&root, &project, bound),
            expected,
            "{bound} decided differently from {plain}"
        );
    }
}

/// The binding proves only itself. Every later item still carries its own
/// proof with the value projected into it, a value that is not literal is not
/// a binding this reads, and a name that steers the shell or the trust anchor
/// of a later fetch keeps its review.
#[test]
fn a_binding_never_proves_what_runs_after_it() {
    let (root, project) = fixture();
    for command in [
        "R=.env; cat $R",
        "R=.; cat $R/.env",
        "R=.; rm one.txt",
        "PATH=/tmp; ls .",
        "IFS=,; ls .",
        "R=$(echo .); ls $R",
        "SSL_CERT_FILE=/tmp/anchor.pem; ls .",
        "CURL_CA_BUNDLE=/tmp/anchor.pem; ls .",
        "REQUESTS_CA_BUNDLE=/tmp/anchor.pem; ls .",
        "PGSSLMODE=disable; ls .",
    ] {
        assert_ne!(
            evaluate(&root, &project, command),
            "allow",
            "{command} was proven by the binding in front of it"
        );
    }
}
