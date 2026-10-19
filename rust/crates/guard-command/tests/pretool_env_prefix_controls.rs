#![cfg(unix)]

use crate::git_helper_fixture as fixture;

use fixture::{evaluate_with_node, git_github_controls, FixtureCleanup};
use serde_json::json;

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
        result
            .reason
            .contains("has a shell syntax error: it leaves a quote open"),
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

#[test]
fn a_heap_only_node_options_setting_points_to_the_sandboxed_node_form() {
    let root = std::env::temp_dir()
        .canonicalize()
        .unwrap()
        .join(format!("guard-env-node-heap-{}", std::process::id()));
    std::fs::create_dir_all(root.join("project")).unwrap();
    let _cleanup = FixtureCleanup(root.clone());
    for command in [
        "NODE_OPTIONS=--max-old-space-size=6144 bunx tsc --noEmit",
        "NODE_OPTIONS=--max-old-space-size=6144 npx tsc --noEmit",
    ] {
        let result = evaluate(&root, command);
        assert_eq!(
            result.minimum_action, "block",
            "{command}: {}",
            result.reason
        );
        assert!(
            result
                .reason
                .contains("the NODE_OPTIONS setting can load code")
                && result.reason.contains(
                    "`node --max-old-space-size=6144 node_modules/typescript/bin/tsc --noEmit`"
                ),
            "{command}: {}",
            result.reason
        );
    }
    // Anything beyond a bare memory size keeps the plain refusal.
    for command in [
        "NODE_OPTIONS='--max-old-space-size=6144 --require ./x.js' bunx tsc --noEmit",
        "NODE_OPTIONS=--max-old-space-size=99999999 bunx tsc --noEmit",
        "NODE_OPTIONS=--require=./x.js bunx tsc --noEmit",
    ] {
        let result = evaluate(&root, command);
        assert_eq!(
            result.minimum_action, "block",
            "{command}: {}",
            result.reason
        );
        assert!(
            result.reason.contains("Run the command without it")
                && !result.reason.contains("more memory"),
            "{command}: {}",
            result.reason
        );
    }
}

/// An `env` that names no program prints the environment and exits. Reading it
/// as an interpreter that launches a file nobody opened blocked `env`,
/// `env -0` and `env | grep '^PATH='` outright, with no approval row to give
/// them. The dump is still a read of every secret the session exports, so it
/// stays at review; what it must not be is unapprovable.
#[test]
fn an_env_that_names_no_program_is_reviewed_rather_than_refused() {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir()
        .canonicalize()
        .unwrap()
        .join(format!("guard-env-dump-{}-{nonce}", std::process::id()));
    std::fs::create_dir_all(root.join("project")).unwrap();
    let _cleanup = FixtureCleanup(root.clone());

    for command in [
        "env",
        "env -0",
        "env | grep '^PATH='",
        "/usr/bin/env | head -5",
        "env -u NODE_OPTIONS | sort",
    ] {
        let result = evaluate(&root, command);
        assert_ne!(
            result.reason_code, "native_command_extension_evaluation_failed",
            "{command}: {}",
            result.reason
        );
        assert!(
            matches!(
                result.minimum_action.as_str(),
                "review" | "sandbox-required"
            ),
            "{command}: {} ({})",
            result.minimum_action,
            result.reason
        );
    }

    // An `env` that does name a program still runs whatever that program is,
    // so the prefix keeps the evaluation failure it arrived with. `-S` and
    // `--split-string` carry the program inside the option's own value, so the
    // launch arrives as one dash-prefixed word and must be read as a launch.
    for command in [
        "env -i sh -c 'echo hi'",
        "env -S bash",
        "env -Sbash",
        "env --split-string=sh",
        "env -iS'sh -c id'",
    ] {
        let result = evaluate(&root, command);
        assert_eq!(
            (result.minimum_action.as_str(), result.reason_code.as_str()),
            ("block", "native_command_extension_evaluation_failed"),
            "{command}: {}",
            result.reason
        );
    }
}
