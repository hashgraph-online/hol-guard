use super::*;

#[test]
fn change_flags_inside_tool_arguments_or_output_are_data() {
    for payload in [
        json!({"tool_name": "Bash", "tool_input": {"command": "ls", "changed": true}}),
        json!({"toolName": "bash", "toolInput": {"command": "ls", "changed": "yes"}}),
        json!({"tool_input": {"previous_hash": "a", "current_hash": "b"}}),
        json!({"tool_response": {"hash_changed": true}}),
        json!({"tool_input": {"arguments": {"changed_capabilities": [1]}}}),
    ] {
        let result = apply_pre_tool_policy(
            &snapshot(policy("allow")),
            &payload,
            generic_result("allow"),
        )
        .unwrap();
        assert_eq!(result.minimum_action, "allow", "{payload}");
    }
    let result = apply_pre_tool_policy(
        &snapshot(policy("allow")),
        &json!({"changed": true, "tool_input": {"command": "ls"}}),
        generic_result("allow"),
    )
    .unwrap();
    assert_eq!(result.minimum_action, "require-reapproval");
    assert_eq!(result.reason_code, "native_policy_reapproval_required");
}

#[test]
fn a_raised_result_names_the_setting_that_raised_it() {
    let result = apply_pre_tool_policy(
        &snapshot(policy("allow")),
        &json!({"changed": true, "tool_input": {"command": "ls"}}),
        generic_result("allow"),
    )
    .unwrap();
    assert_eq!(
        result.reason,
        "HOL Guard requires fresh approval under the installed policy's changed artifact setting."
    );

    let mut risky = policy("allow");
    risky
        .risk_actions
        .insert("execution".into(), "require-reapproval".into());
    let result = apply_pre_tool_policy(
        &snapshot(risky),
        &json!({"tool_input": {"command": "ls"}}),
        generic_result("review"),
    )
    .unwrap();
    assert_eq!(result.reason_code, "native_policy_reapproval_required");
    assert_eq!(
        result.reason,
        "HOL Guard requires fresh approval under the installed policy's command execution setting."
    );

    // The first setting to reach the floor is named, not a later equal one.
    let mut subprocess = policy("allow");
    subprocess.subprocess_action = "review".into();
    subprocess
        .risk_actions
        .insert("execution".into(), "review".into());
    let result =
        apply_pre_tool_policy(&snapshot(subprocess), &json!({}), generic_result("allow")).unwrap();
    assert_eq!(
        result.reason,
        "HOL Guard requires review under the installed policy's subprocess setting."
    );
}

#[test]
fn network_floor_decides_a_proven_plain_web_fetch() {
    let mut fetch = generic_result("allow");
    fetch.action.action_type = PreToolActionTypeV1::Network;
    fetch.action.operation = PreToolOperationV1::Request;
    fetch.reason_code = "native_plain_web_request".into();
    let payload =
        json!({"tool_name": "WebFetch", "tool_input": {"url": "https://status.example.test/"}});
    for (setting, minimum, decision) in [
        ("allow", "allow", "allow"),
        ("warn", "warn", "allow"),
        ("review", "review", "deny"),
        ("block", "block", "deny"),
    ] {
        let mut network = policy("allow");
        network.new_network_domain_action = setting.into();
        let result = apply_pre_tool_policy(&snapshot(network), &payload, fetch.clone()).unwrap();
        assert_eq!(result.minimum_action, minimum, "{setting}");
        assert_eq!(result.decision, decision, "{setting}");
    }
}

#[test]
fn proven_no_scripts_install_skips_only_the_package_script_floor() {
    let mut review = generic_result("review");
    review.action.action_type = PreToolActionTypeV1::Package;
    review.action.operation = PreToolOperationV1::Install;
    review.reason_code = "native_package_review".into();
    let mut script_policy = policy("allow");
    script_policy
        .risk_actions
        .insert("package_script".into(), "require-reapproval".into());
    let installed = snapshot(script_policy);
    let apply = |command: &str| {
        let payload = json!({"tool_name": "Bash", "tool_input": {"command": command}});
        apply_pre_tool_policy(&installed, &payload, review.clone()).unwrap()
    };
    for command in [
        "bun install --frozen-lockfile --ignore-scripts",
        "npm ci --ignore-scripts",
        "pnpm install --ignore-scripts --ignore-pnpmfile",
        "pnpm install --frozen-lockfile --ignore-scripts --ignore-pnpmfile",
    ] {
        let result = apply(command);
        assert_eq!(result.minimum_action, "review", "{command}");
        assert_eq!(result.reason_code, "native_package_review", "{command}");
    }
    // A held install names the forms the setting skips, so the agent can
    // restore dependencies instead of stopping. Every form named is proven.
    let held = apply("bun install --frozen-lockfile");
    for form in [
        "bun install --frozen-lockfile --ignore-scripts",
        "npm ci --ignore-scripts",
        "pnpm install --frozen-lockfile --ignore-scripts --ignore-pnpmfile",
    ] {
        assert!(held.reason.contains(&format!("`{form}`")), "{form}");
        assert_eq!(apply(form).reason_code, "native_package_review", "{form}");
    }
    // Every package command reaches here as an install, so the advice
    // follows the command text: a script run gets none.
    let script = apply("bun scripts/report.ts --json");
    assert_eq!(script.reason_code, "native_policy_reapproval_required");
    assert!(!script.reason.contains("--ignore-scripts"));
    // Commands that are not installs get no install advice.
    let mut build = review.clone();
    build.action.operation = PreToolOperationV1::Execute;
    let payload = json!({"tool_name": "Bash", "tool_input": {"command": "npm run build"}});
    let result = apply_pre_tool_policy(&installed, &payload, build).unwrap();
    assert_eq!(result.reason_code, "native_policy_reapproval_required");
    assert!(!result.reason.contains("--ignore-scripts"));
    for command in [
        "bun install --frozen-lockfile",
        "bun install --ignore-scripts=false",
        "pnpm install --ignore-scripts",
        "yarn install --mode=skip-build",
        "npm run build",
        "bun run build",
        "npm ci --ignore-scripts && npm run build",
        "npm_config_ignore_scripts=false npm ci --ignore-scripts",
    ] {
        let result = apply(command);
        assert_eq!(result.minimum_action, "require-reapproval", "{command}");
        assert_eq!(
            result.reason_code, "native_policy_reapproval_required",
            "{command}"
        );
    }
    // A stronger default floor still applies to the proven form.
    let mut strict = policy("block");
    strict
        .risk_actions
        .insert("package_script".into(), "require-reapproval".into());
    let payload =
        json!({"tool_name": "Bash", "tool_input": {"command": "npm ci --ignore-scripts"}});
    let blocked = apply_pre_tool_policy(&snapshot(strict), &payload, review).unwrap();
    assert_eq!(blocked.minimum_action, "block");
}

#[test]
fn proven_lockfile_install_satisfies_only_the_unknown_publisher_review() {
    let mut proven = generic_result("allow");
    proven.action.action_type = PreToolActionTypeV1::Package;
    proven.action.operation = PreToolOperationV1::Install;
    proven.reason_code = "native_exact_safe_lockfile_install".into();
    let payload = json!({"tool_name": "Bash", "tool_input": {
        "command": "bun install --frozen-lockfile --ignore-scripts"}});
    let mut scripts = policy("allow");
    scripts
        .risk_actions
        .insert("package_script".into(), "require-reapproval".into());
    let result = apply_pre_tool_policy(&snapshot(scripts), &payload, proven.clone()).unwrap();
    assert_eq!(result.minimum_action, "allow");
    assert_eq!(result.decision, "allow");
    assert_eq!(result.reason_code, "native_exact_safe_lockfile_install");

    // Any other package allow still owes the unknown publisher review.
    let mut other = proven.clone();
    other.reason_code = "native_test".into();
    let result = apply_pre_tool_policy(&snapshot(policy("allow")), &payload, other).unwrap();
    assert_eq!(result.minimum_action, "review");
    assert_eq!(result.reason_code, "native_policy_review_required");

    // A stronger publisher action or default floor still applies.
    let mut strict = policy("allow");
    strict.unknown_publisher_action = "block".into();
    let result = apply_pre_tool_policy(&snapshot(strict), &payload, proven.clone()).unwrap();
    assert_eq!(result.minimum_action, "block");
    let result = apply_pre_tool_policy(&snapshot(policy("review")), &payload, proven).unwrap();
    assert_eq!(result.minimum_action, "review");
}
