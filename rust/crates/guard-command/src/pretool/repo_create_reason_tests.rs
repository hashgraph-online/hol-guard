use super::super::evaluate_pre_tool_with_context;
use crate::CommandModelRequestV1;

fn review(command: &str) -> (String, String, String) {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .canonicalize()
        .unwrap();
    let root = root.to_str().unwrap();
    let request = CommandModelRequestV1 {
        command: command.to_owned(),
        dialect: "posix".to_owned(),
        transport: "shell_string".to_owned(),
        extraction_provenance: "guard-shell".to_owned(),
    };
    let decision = evaluate_pre_tool_with_context(&request, Some(root), Some(root)).unwrap();
    (
        decision.minimum_action,
        decision.reason_code,
        decision.reason,
    )
}

#[test]
fn a_public_or_pushing_repo_create_names_the_private_alternative() {
    for command in [
        "gh repo create todo-app --public --source=. --push",
        "gh repo create todo-app --public",
        "gh repo create todo-app --internal --source .",
        "gh repo create todo-app --private --source=. --push",
        "gh repo create todo-app --source=. --remote origin",
        "/usr/local/bin/gh repo create todo-app --public -d \"A small todo app\"",
    ] {
        let (action, code, reason) = review(command);
        assert_eq!(action, "review", "{command}");
        assert_eq!(code, "native_command_review_required", "{command}");
        assert!(
            reason.contains("Creating it private runs without review"),
            "{command}: {reason}"
        );
        assert!(!reason.contains("todo-app"), "{reason}");
    }
    let (_, _, reason) = review("gh repo create todo-app --public --source=. --push");
    assert!(reason.contains("git push -u origin <branch>"), "{reason}");
    let (_, _, reason) = review("gh repo create todo-app --public");
    assert!(!reason.contains("git push"), "{reason}");
}

#[test]
fn repo_creates_the_private_form_would_not_admit_keep_the_generic_reason() {
    for command in [
        "gh repo create example-org/todo-app --public",
        "gh repo create todo-app --public --template example-org/base",
        "gh repo create todo-app --public --source ../other",
        "gh repo create todo-app --public --clone",
        "gh repo create todo-app --public -d $NOTES",
        "GH_HOST=example.com gh repo create todo-app --public",
        "gh repo delete todo-app --yes",
        "gh repo create todo-app --public && git status",
    ] {
        let (_, _, reason) = review(command);
        assert!(
            !reason.contains("Creating it private"),
            "{command}: {reason}"
        );
    }
}

#[test]
fn the_private_alternative_runs_without_review() {
    for command in [
        "gh repo create todo-app --private --source=.",
        "gh repo create todo-app --private",
        "gh repo create todo-app --source . --remote origin --private",
        "gh repo create todo-app --private -d \"A small todo app\" --add-readme",
        "gh repo create todo-app --private --gitignore Node --license mit",
    ] {
        let (action, code, _) = review(command);
        assert_eq!(action, "allow", "{command}: {code}");
    }
    for command in [
        "gh repo create todo-app --private --source=. --push",
        "gh repo create todo-app --private --clone",
        "gh repo create todo-app --private --source ../other",
        "gh repo create todo-app --private --template example-org/base",
        "gh repo create example-org/todo-app --private",
        "gh repo create todo-app --private -d @notes.txt",
        "gh repo create todo-app --private -d $NOTES",
        "GH_HOST=example.com gh repo create todo-app --private",
        "gh repo create todo-app",
        "gh repo create todo-app --public",
        "gh repo create todo-app --internal",
        // A directory in the executable never reaches the basename allow.
        "/usr/local/bin/gh repo create todo-app --private --gitignore Node --license mit",
    ] {
        let (action, _, _) = review(command);
        assert_ne!(action, "allow", "{command}");
    }
}
