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
        "git status && gh repo create example-org/todo-app --public",
        "gh repo create one --public && gh repo create two --public",
        "GH_HOST=example.com gh repo create todo-app --public && git status",
        "cd app && gh repo create todo-app --public --source .",
    ] {
        let (_, _, reason) = review(command);
        assert!(
            !reason.contains("Creating it private"),
            "{command}: {reason}"
        );
    }
}

#[test]
fn a_chained_public_repo_create_names_its_step_and_the_private_alternative() {
    for (command, step) in [
        (
            "git init -q && git add -A && git commit -qm \"Simple todo CLI app\" && gh repo create todo-app --public --source=. --push",
            4,
        ),
        ("gh repo create todo-app --public && git status", 1),
        ("git add -A; gh repo create todo-app --internal --source .", 2),
    ] {
        let (action, code, reason) = review(command);
        assert_eq!(action, "review", "{command}");
        assert_eq!(code, "native_command_review_required", "{command}");
        assert!(
            reason.contains(&format!("step {step} of this command")),
            "{command}: {reason}"
        );
        assert!(
            reason.contains("Run the other steps as separate commands"),
            "{reason}"
        );
        assert!(
            reason.contains("Creating it private runs without review"),
            "{reason}"
        );
        assert!(!reason.contains("todo-app"), "{reason}");
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

#[test]
fn a_push_to_the_remote_a_private_create_adds_names_both_steps() {
    for (command, create, push) in [
        (
            "gh repo create todo-app --private --source=. && git push -u origin main",
            1,
            2,
        ),
        (
            "gh repo create todo-app --source . --private --remote origin -d \"A small app\" && git push --set-upstream origin main",
            1,
            2,
        ),
        (
            "git add . && git commit -m \"Initial commit\" && gh repo create todo-app -s . --private && git push origin HEAD",
            3,
            4,
        ),
        (
            "gh repo create todo-app --private --source=./ --remote=origin; git push -u origin main",
            1,
            2,
        ),
    ] {
        let (action, code, reason) = review(command);
        assert_eq!(action, "review", "{command}");
        assert_eq!(code, "native_command_review_required", "{command}");
        assert!(
            reason.contains(&format!(
                "step {push} of this command (`git push`) pushes to the remote that step {create} (`gh repo create`) adds"
            )),
            "{command}: {reason}"
        );
        assert!(
            reason.contains("Run the steps as separate commands, in order"),
            "{reason}"
        );
        assert!(!reason.contains("todo-app"), "{reason}");
        assert!(!reason.contains("main"), "{reason}");
    }
}

#[test]
fn pushes_the_create_step_does_not_set_up_keep_other_reasons() {
    for command in [
        // No remote is added, or it is added under another name.
        "gh repo create todo-app --private && git push -u origin main",
        "gh repo create todo-app --private --source=. --remote upstream && git push -u origin main",
        // The push runs before the remote exists, or there are two of them.
        "git push -u origin main && gh repo create todo-app --private --source=.",
        "gh repo create todo-app --private --source=. && git push origin main && git push origin topic",
        // A push that is not the plain origin form, or another create shape.
        "gh repo create todo-app --private --source=. && git push --force origin main",
        "gh repo create todo-app --private --source=. && git -C ../other push origin main",
        "gh repo create example-org/todo-app --private --source=. && git push -u origin main",
        "GH_HOST=example.com gh repo create todo-app --private --source=. && git push -u origin main",
        "/usr/local/bin/gh repo create todo-app --private --source=. && git push -u origin main",
        "cd app && gh repo create todo-app --private --source=. && git push -u origin main",
    ] {
        let (action, _, reason) = review(command);
        assert_ne!(action, "allow", "{command}");
        assert!(
            !reason.contains("Guard cannot check a remote before it exists"),
            "{command}: {reason}"
        );
    }
}
