#![cfg(unix)]

use crate::git_helper_fixture as fixture;

use fixture::{evaluate_with_node, git_github_controls, FixtureCleanup};
use serde_json::json;

const HOME_TEXT: &str = "writes to a path under the home folder";

fn evaluate(root: &std::path::Path, command: &str) -> guard_contracts::PreToolResultV1 {
    evaluate_with_node(
        "zcode",
        "PreToolUse",
        &json!({"tool_name":"bash", "tool_input":{"command":command}}),
        Some(&git_github_controls("default", "default")),
        root,
        root.join("project").to_str(),
    )
}

#[test]
fn a_redirect_into_the_home_folder_stays_blocked_and_says_why() {
    let nonce = crate::unique_nanos::unique_nanos();
    let root = std::env::temp_dir().canonicalize().unwrap().join(format!(
        "guard-home-redirect-{}-{nonce}",
        std::process::id()
    ));
    std::fs::create_dir_all(root.join("project")).unwrap();
    let _cleanup = FixtureCleanup(root.clone());

    for command in [
        "echo x >> ~/notes.txt",
        "echo x >> ~/.zshrc",
        "gh pr view 12 --json state > ~/pr.json",
        "for x in a; do gh pr view 12 > ~/out.json; done",
        "git status && echo x >> ~/.profile",
    ] {
        let result = evaluate(&root, command);
        assert_eq!(
            result.minimum_action, "block",
            "{command}: {}",
            result.reason
        );
        assert_eq!(
            result.reason_code, "native_command_extension_evaluation_failed",
            "{command}"
        );
        assert!(
            result.reason.contains(HOME_TEXT),
            "{command}: {}",
            result.reason
        );
        assert!(
            !result.reason.contains("script"),
            "{command}: {}",
            result.reason
        );
    }

    let result = evaluate(&root, "echo x >> notes.txt");
    assert!(!result.reason.contains(HOME_TEXT), "{}", result.reason);

    // A command that cannot be matched with its output in the project keeps
    // that reason: the home folder is not what stopped it. Quoted text that
    // only looks like a redirect is not one either.
    let mut independent = 0;
    for program in [
        "bash ./missing.sh",
        "eval \"$CMD\"",
        "xargs sh -c 'echo x' < list.txt",
    ] {
        let baseline = evaluate(&root, &format!("{program} > out.log"));
        if baseline.reason_code != "native_command_extension_evaluation_failed" {
            continue;
        }
        independent += 1;
        for command in [
            format!("{program} > ~/out.log"),
            format!("{program} '> ~/notes.txt' > out.log"),
        ] {
            let result = evaluate(&root, &command);
            assert_eq!(
                result.reason_code, baseline.reason_code,
                "{command}: {}",
                result.reason
            );
            assert!(
                !result.reason.contains(HOME_TEXT),
                "{command}: {}",
                result.reason
            );
        }
    }
    assert!(independent > 0, "no command failed evaluation on its own");

    // A quoted `~` is a literal folder name the shell never expands.
    for command in ["echo x > '~/notes.txt'", "echo x > \"~/notes.txt\""] {
        let result = evaluate(&root, command);
        assert!(
            !result.reason.contains(HOME_TEXT),
            "{command}: {}",
            result.reason
        );
    }

    // The rest of the target stays in the probe, so a substitution that fails
    // on its own keeps the reason it gets inside the project.
    let baseline = evaluate(&root, "echo x > ./$(./missing.sh)");
    if baseline.reason_code == "native_command_extension_evaluation_failed" {
        let result = evaluate(&root, "echo x > ~/$(./missing.sh)");
        assert_eq!(result.reason, baseline.reason);
    }
}
