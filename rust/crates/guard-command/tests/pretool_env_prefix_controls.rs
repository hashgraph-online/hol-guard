#![cfg(unix)]

use crate::git_helper_fixture as fixture;

use fixture::{evaluate_pre_tool_envelope_with_context, git_github_controls, FixtureCleanup};
use serde_json::json;

fn evaluate(root: &std::path::Path, command: &str) -> guard_contracts::PreToolResultV1 {
    evaluate_pre_tool_envelope_with_context(
        "zcode",
        "PreToolUse",
        &json!({"tool_name":"bash", "tool_input":{"command":command}}),
        Some(&git_github_controls("default", "default")),
        None,
        root.to_str(),
        root.join("project").to_str(),
    )
}

#[test]
fn a_reviewable_setting_before_an_unmodeled_script_reaches_ordinary_review() {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir()
        .canonicalize()
        .unwrap()
        .join(format!("guard-env-prefix-{}-{nonce}", std::process::id()));
    std::fs::create_dir_all(root.join("project/scripts")).unwrap();
    let _cleanup = FixtureCleanup(root.clone());
    std::fs::write(root.join("project/scripts/report.mjs"), "console.log(1)\n").unwrap();
    let modules = root.join("project/node_modules");

    for command in [
        format!(
            "REPORT_SOURCE={} REPORT_DIR=.tmp/report node scripts/report.mjs",
            modules.display()
        ),
        format!(
            "env REPORT_SOURCE={} REPORT_DIR=.tmp/report node scripts/report.mjs",
            modules.display()
        ),
    ] {
        let result = evaluate(&root, &command);
        // Hosts with the workspace sandbox run the script there instead.
        assert!(
            matches!(
                (result.minimum_action.as_str(), result.reason_code.as_str()),
                ("review", "native_command_review_required")
                    | ("sandbox-required", "native_workspace_containment_required")
            ),
            "{command}: {}",
            result.reason
        );
    }

    let result = evaluate(&root, &format!("REPORT_SOURCE={} ls", modules.display()));
    assert_eq!(result.minimum_action, "review", "{}", result.reason);
    assert!(
        result
            .reason
            .contains("the REPORT_SOURCE setting can change how this command runs"),
        "{}",
        result.reason
    );

    let result = evaluate(
        &root,
        &format!("NODE_PATH={} node scripts/report.mjs", modules.display()),
    );
    // The modules sit inside the workspace, so the sandbox bounds them too.
    assert!(
        matches!(
            (result.minimum_action.as_str(), result.reason_code.as_str()),
            ("review", "native_command_review_required")
                | ("sandbox-required", "native_workspace_containment_required")
        ),
        "{}",
        result.reason
    );

    let result = evaluate(
        &root,
        &format!("NODE_PATH={} gh api user", modules.display()),
    );
    assert_eq!(result.minimum_action, "block", "{}", result.reason);
    assert!(
        result
            .reason
            .contains("the NODE_PATH setting can load code")
            && result.reason.contains("Run the command without it"),
        "{}",
        result.reason
    );

    // A canonical, existing `node_modules` directory inside the working tree
    // is a dependency tree the project already trusts: the setting is named in
    // an ordinary review (or the workspace sandbox) instead of the hard block,
    // and never settles lower.
    std::fs::create_dir_all(&modules).unwrap();
    let modules = modules.canonicalize().unwrap();
    for command in [
        format!("NODE_PATH={} node scripts/report.mjs", modules.display()),
        format!(
            "env NODE_PATH={} node scripts/report.mjs",
            modules.display()
        ),
    ] {
        let result = evaluate(&root, &command);
        assert!(
            matches!(
                result.minimum_action.as_str(),
                "review" | "sandbox-required"
            ),
            "{command}: {}",
            result.reason
        );
        assert_ne!(
            result.reason_code, "native_command_extension_evaluation_failed",
            "{command}"
        );
    }
    // Any other plain module path in front of `node` only picks which code
    // the script loads, so it reaches review or the sandbox, never allow.
    std::fs::create_dir_all(root.join("project/vendor")).unwrap();
    for command in [
        format!(
            "NODE_PATH={} node scripts/report.mjs",
            root.join("project/vendor").display()
        ),
        format!(
            "NODE_PATH={}:/usr/lib node scripts/report.mjs",
            modules.display()
        ),
        "NODE_PATH=node_modules node scripts/report.mjs".to_owned(),
        format!(
            "NODE_PATH={}/../project/node_modules node scripts/report.mjs",
            modules.display()
        ),
    ] {
        let result = evaluate(&root, &command);
        assert!(
            matches!(
                result.minimum_action.as_str(),
                "review" | "sandbox-required"
            ),
            "{command}: {} {}",
            result.minimum_action,
            result.reason
        );
    }
    // Loader hooks keep the block.
    let result = evaluate(
        &root,
        "NODE_OPTIONS=--require=./hook.js node scripts/report.mjs",
    );
    assert_eq!(result.minimum_action, "block", "{}", result.reason);

    for command in [
        "NODE_OPTIONS=--require=./hook.js node scripts/report.mjs",
        "BASH_ENV=./hook.sh node scripts/report.mjs",
    ] {
        assert_ne!(
            evaluate(&root, command).minimum_action,
            "allow",
            "{command}"
        );
    }
}

#[test]
fn an_open_quote_is_named_instead_of_the_extension_controls() {
    let root = std::env::temp_dir().canonicalize().unwrap().join(format!(
        "guard-open-quote-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(root.join("project")).unwrap();
    let _cleanup = FixtureCleanup(root.clone());

    let command = "gh api graphql -f query='mutation($t: ID!) { resolveReviewThread(input: {threadId: $t}) { thread { isResolved } } }' -f t=PRRT_example'}";
    let result = evaluate(&root, command);
    assert_eq!(
        (result.minimum_action.as_str(), result.reason_code.as_str()),
        ("block", "native_command_extension_evaluation_failed"),
        "{}",
        result.reason
    );
    assert!(
        result.reason.contains("leaves a quote open"),
        "{}",
        result.reason
    );
}

#[test]
fn a_substituted_setting_is_named_with_a_safe_alternative() {
    let root = std::env::temp_dir()
        .canonicalize()
        .unwrap()
        .join(format!("guard-env-substitution-{}", std::process::id()));
    std::fs::create_dir_all(root.join("project")).unwrap();
    let _cleanup = FixtureCleanup(root.clone());
    for command in [
        "SERVICE_TOKEN=$(echo x) echo done",
        "env SERVICE_TOKEN=$(echo x) echo done",
        "SERVICE_TOKEN=`echo x` echo done",
    ] {
        let result = evaluate(&root, command);
        assert_eq!(
            result.minimum_action, "block",
            "{command}: {}",
            result.reason
        );
        assert!(
            result.reason.contains("SERVICE_TOKEN")
                && result.reason.contains("command substitution")
                && result.reason.contains("run the commands separately"),
            "{command}: {}",
            result.reason
        );
    }
}

#[test]
fn a_credential_setting_is_named_with_a_safe_alternative() {
    let root = std::env::temp_dir()
        .canonicalize()
        .unwrap()
        .join(format!("guard-env-credential-{}", std::process::id()));
    std::fs::create_dir_all(root.join("project/scripts")).unwrap();
    let _cleanup = FixtureCleanup(root.clone());
    std::fs::write(root.join("project/scripts/report.ts"), "console.log(1)\n").unwrap();
    for (command, setting) in [
        ("REPORT_API_KEY=fixture-value ls", "REPORT_API_KEY"),
        (
            "REPORT_API_KEY=fixture-value REPORT_ID=7 bun scripts/report.ts --json",
            "REPORT_API_KEY",
        ),
        (
            "REPORT_ID=7 SERVICE_TOKEN=fixture-value node scripts/report.ts",
            "SERVICE_TOKEN",
        ),
        ("env SERVICE_TOKEN=fixture-value ls", "SERVICE_TOKEN"),
    ] {
        let result = evaluate(&root, command);
        assert_eq!(
            (result.minimum_action.as_str(), result.reason_code.as_str()),
            ("block", "native_command_extension_evaluation_failed"),
            "{command}: {}",
            result.reason
        );
        assert!(
            result.reason.contains(setting)
                && result.reason.contains("passes a credential")
                && result.reason.contains("ask the user to run the command")
                && !result.reason.contains("fixture-value")
                && !result.reason.contains("hol-guard doctor"),
            "{command}: {}",
            result.reason
        );
    }
}
