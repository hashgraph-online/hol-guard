#![cfg(unix)]

#[allow(dead_code)]
#[path = "support/git_helper_fixture.rs"]
mod fixture;

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
        assert_eq!(
            (result.minimum_action.as_str(), result.reason_code.as_str()),
            ("review", "native_command_review_required"),
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
    // an ordinary review instead of the hard block, and never settles lower.
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
        assert_eq!(
            result.minimum_action, "review",
            "{command}: {}",
            result.reason
        );
        assert_ne!(
            result.reason_code, "native_command_extension_evaluation_failed",
            "{command}"
        );
    }
    // Other paths and other loader settings keep the block.
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
        "NODE_OPTIONS=--require=./hook.js node scripts/report.mjs".to_owned(),
    ] {
        let result = evaluate(&root, &command);
        assert_eq!(
            result.minimum_action, "block",
            "{command}: {}",
            result.reason
        );
    }

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
