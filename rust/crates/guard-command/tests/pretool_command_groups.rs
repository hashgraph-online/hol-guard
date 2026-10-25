#![cfg(unix)]

use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use serde_json::json;

fn evaluate(harness: &str, command: &str, root: &std::path::Path) -> String {
    evaluate_pre_tool_envelope_with_context(
        harness,
        "PreToolUse",
        &json!({"tool_name":"bash", "tool_input":{"command":command}}),
        None,
        None,
        root.to_str(),
        root.to_str(),
    )
    .minimum_action
}

/// A whole command the shell runs as one group owns exactly what the list
/// inside it owns. `(cd src && npm test)` is how an agent runs a build without
/// moving the shell it came from, and `{ … ; }` is the same list without the
/// child; both reached the compound-shell refusal and asked, whatever the list
/// was. The list now decides, so a group around proven reads is proven and a
/// group around a write or a secret is not.
#[test]
fn a_whole_command_group_is_read_as_the_list_inside_it() {
    let nonce = crate::unique_nanos::unique_nanos();
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/command-group-fixtures")
        .join(format!("fixture-{}-{nonce}", std::process::id()));
    std::fs::create_dir_all(root.join("project")).unwrap();
    let root = std::fs::canonicalize(root).unwrap();
    let project = root.join("project");
    std::fs::write(project.join("one.txt"), "ordinary fixture\n").unwrap();
    std::fs::write(project.join(".env"), "SYNTHETIC_ONLY=fixture\n").unwrap();
    let inside = project.display().to_string();

    for harness in ["omp", "zcode", "claude-code", "codex", "cursor"] {
        for (command, allowed) in [
            // The list inside the group is the one the plain spelling proves.
            (format!("(cd {inside} && cat one.txt)"), true),
            (format!("( cd {inside} && cat one.txt )"), true),
            (format!("(cat {inside}/one.txt)"), true),
            (format!("{{ cd {inside} && cat one.txt; }}"), true),
            (format!("{{ cat {inside}/one.txt; }}"), true),
            // A group's directory change does not outlive it, so reading the
            // list as though it did can only widen what the command owns.
            (format!("(cd {inside}; cat one.txt; cat one.txt)"), true),
            // What the list is refused for, the group is refused for.
            (format!("(cd {inside} && cat .env)"), false),
            (format!("(cd {inside} && rm one.txt)"), false),
            (format!("{{ cd {inside} && cat .env; }}"), false),
            (format!("(cd {inside} && cat $(echo one.txt))"), false),
            // Text outside the brackets is text the list does not account
            // for. A group that is only one item of a longer list is left to
            // the path that already reads such a list, not stripped here.
            (format!("(cd {inside} && cat one.txt) > out.txt"), false),
            (format!("(cd {inside} && cat one.txt) | cat"), false),
            (format!("(cd {inside} && cat one.txt) &"), false),
            // A second bracket of either kind is a nesting or an expansion
            // this pass has not read.
            (format!("((cd {inside} && cat one.txt))"), false),
            (format!("(cd {inside} && cat \"${{HOME}}/one.txt\")"), false),
            // A newline ends a list the way `;` does, so a brace group
            // written over two lines is the group its one-line spelling is.
            (format!("{{ cd {inside} && cat one.txt\n}}"), true),
            (format!("{{ cat {inside}/one.txt\n  }}"), true),
            (format!("{{ cd {inside} && cat .env\n}}"), false),
            // `{` is a word unless whitespace separates it from the list, and
            // the list has to be terminated for `}` to be a bracket.
            (format!("{{cd {inside} && cat one.txt; }}"), false),
            (format!("{{ cd {inside} && cat one.txt }}"), false),
        ] {
            assert_eq!(
                evaluate(harness, &command, &root) == "allow",
                allowed,
                "{harness}: {command}"
            );
        }
    }
    std::fs::remove_dir_all(root).unwrap();
}
