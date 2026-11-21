//! Contract tests for the `package_review_plan` resident op.

use guard_contracts::{PackageReviewPlanRequestV1, PACKAGE_AUTHORITY_REQUEST_SCHEMA};
use serde_json::{json, Value};

use super::evaluate_package_review_plan;
use crate::package_authority_op::request_digest;

fn request(workspace: &str, payload: Value) -> PackageReviewPlanRequestV1 {
    PackageReviewPlanRequestV1 {
        schema: PACKAGE_AUTHORITY_REQUEST_SCHEMA.to_owned(),
        request_id: "package-review-plan-1".to_owned(),
        guard_home: "/tmp/guard-home".to_owned(),
        workspace: workspace.to_owned(),
        harness: "codex".to_owned(),
        payload,
        home_dir: None,
        review_reason: None,
    }
}

fn plan(payload: Value) -> Value {
    let workspace = tempfile::tempdir().expect("workspace");
    let input = request(&workspace.path().to_string_lossy(), payload);
    let bytes = evaluate_package_review_plan(&input).expect("request must encode a result");
    let decoded: Value = serde_json::from_slice(&bytes).expect("result must decode");
    decoded["payload"].clone()
}

fn shell(command: &str) -> Value {
    json!({"tool_name": "Bash", "tool_input": {"command": command}})
}

#[test]
fn an_unproven_npm_install_is_planned_for_blocks_only() {
    let answer = plan(shell("npm install minimist@1.2.8"));
    let metadata = &answer["artifact"]["metadata"];
    assert_eq!(metadata["package_manager"], "npm");
    assert_eq!(metadata["intent_kind"], "install");
    assert!(metadata.get("verified_npm_version").is_none());
    assert_eq!(answer["may_allow"], false);
}

#[test]
fn exec_flows_are_planned_for_blocks_only() {
    for command in [
        "npx create-vite@5.1.0",
        "npm exec --package=create-vite@5.1.0 create-vite",
        "pnpm dlx create-next-app@14.2.0",
        "yarn dlx @redwoodjs/create-redwood-app@6.0.0",
        "bunx @angular/cli@19.0.0",
    ] {
        let answer = plan(shell(command));
        assert_eq!(
            answer["artifact"]["metadata"]["intent_kind"], "execute",
            "{command}"
        );
        assert_eq!(answer["may_allow"], false, "{command}");
    }
}

/// The edge gives `npx` and `bunx` a command review. Their packages are still
/// fetched, so the review is planned, for a block verdict only; any other
/// command under that reason is left to the review.
#[test]
fn a_command_review_plans_only_npx_and_bunx_launches() {
    let workspace = tempfile::tempdir().expect("workspace");
    let answer = |command: &str| {
        let mut input = request(&workspace.path().to_string_lossy(), shell(command));
        input.review_reason = Some(super::LAUNCH_REVIEW_REASON.to_owned());
        let bytes = evaluate_package_review_plan(&input).expect("request must encode a result");
        serde_json::from_slice::<Value>(&bytes).expect("result")["payload"].clone()
    };
    for command in ["npx create-vite@5.1.0", "bunx @angular/cli@19.0.0"] {
        let planned = answer(command);
        assert_eq!(
            planned["artifact"]["metadata"]["intent_kind"], "execute",
            "{command}"
        );
        assert_eq!(planned["may_allow"], false, "{command}");
    }
    // The package a launch fetches is the one the bundle judges, not the
    // executable it then runs.
    for command in [
        "npx -p flagged-package@1.0.0 node --version",
        "bunx --bun flagged-package@1.0.0",
        "npx --cache /tmp/npm-cache flagged-package@1.0.0",
    ] {
        assert_eq!(
            answer(command)["artifact"]["metadata"]["targets"][0]["package_name"],
            "flagged-package",
            "{command}"
        );
    }
    for command in [
        "npm install zod --ignore-scripts --allow-git=none",
        "pnpm dlx create-next-app@14.2.0",
        "npm exec --package=create-vite@5.1.0 create-vite",
        // The evaluator judges one package, so a launch that fetches
        // several stays with its review.
        "npx -p left-pad -p flagged-package node",
        "npx --package=left-pad --package=flagged-package node",
        // The evaluator reads the redacted command, which hides the URL.
        "npx --registry https://registry.example flagged-package@1.0.0",
    ] {
        assert_eq!(
            answer(command),
            json!({"artifact": null, "may_allow": false, "workspace": null, "keyed": false}),
            "{command}"
        );
    }
}

/// Copilot sends its command in `toolArgs`, as a map or as JSON text.
#[test]
fn copilot_tool_args_are_read() {
    for tool_args in [
        json!({"command": "npm install minimist@1.2.8"}),
        json!("{\"command\": \"npm install minimist@1.2.8\"}"),
    ] {
        let answer = plan(json!({"toolName": "bash", "toolArgs": tool_args}));
        assert_eq!(answer["artifact"]["metadata"]["intent_kind"], "install");
    }
}

#[test]
fn commands_the_evaluator_does_not_read_plan_nothing() {
    for payload in [
        shell("pip install requests"),
        shell("npm install minimist && rm -rf build"),
        shell("npm install $PKG"),
        shell("npm run build"),
        json!({"tool_name": "Bash"}),
        json!("not a map"),
    ] {
        let answer = plan(payload.clone());
        assert_eq!(
            answer,
            json!({"artifact": null, "may_allow": false, "workspace": null, "keyed": false}),
            "{payload}"
        );
    }
}

#[test]
fn a_relative_workspace_or_foreign_schema_is_refused() {
    let input = request("relative/workspace", shell("npm install zod"));
    assert_eq!(
        evaluate_package_review_plan(&input).unwrap_err(),
        "native_package_review_plan_invalid"
    );
    let workspace = std::env::temp_dir();
    let mut input = request(&workspace.to_string_lossy(), shell("npm install zod"));
    input.schema = "guard-other-request.v1".to_owned();
    assert_eq!(
        evaluate_package_review_plan(&input).unwrap_err(),
        "native_package_review_plan_schema_mismatch"
    );
}

#[test]
fn the_request_digest_covers_the_fields_the_caller_sent() {
    let workspace = std::env::temp_dir();
    let sent = json!({
        "schema": PACKAGE_AUTHORITY_REQUEST_SCHEMA,
        "request_id": "package-review-plan-1",
        "guard_home": "/tmp/guard-home",
        "workspace": workspace.to_string_lossy(),
        "harness": "codex",
        "payload": shell("npm install zod"),
        "home_dir": null,
    });
    let input: PackageReviewPlanRequestV1 =
        serde_json::from_value(sent.clone()).expect("request must decode");
    let bytes = evaluate_package_review_plan(&input).expect("request must encode a result");
    let decoded: Value = serde_json::from_slice(&bytes).expect("result must decode");
    assert_eq!(
        decoded["request_sha256"].as_str(),
        Some(request_digest(&sent).expect("digest").as_str())
    );
}

/// A standard npm on the stamped `PATH` proves the version, so the
/// evaluator's verdict may let the install continue.
#[cfg(unix)]
#[test]
fn a_proven_npm_install_may_continue() {
    use std::fs;
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::path::Path;

    fn executable(path: &Path) {
        fs::write(path, "#!/bin/sh\n").expect("file must be writable");
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).expect("mode");
    }
    let root = tempfile::tempdir().expect("root");
    let bin = root.path().join("prefix").join("bin");
    let package = root.path().join("prefix/lib/node_modules/npm");
    fs::create_dir_all(package.join("bin")).expect("npm package");
    fs::create_dir_all(&bin).expect("bin");
    executable(&package.join("bin").join("npm-cli.js"));
    executable(&bin.join("node"));
    fs::write(
        package.join("package.json"),
        json!({"name": "npm", "version": "11.9.0"}).to_string(),
    )
    .expect("manifest");
    symlink(package.join("bin").join("npm-cli.js"), bin.join("npm")).expect("npm link");
    let workspace = root.path().join("workspace");
    fs::create_dir_all(&workspace).expect("workspace");
    let answer = |command: &str| {
        let mut payload = shell(command);
        payload["guard_execution_environment"] = json!({
            "environment_names": ["PATH", "HOME"],
            "path": bin.to_string_lossy(),
            "home": root.path().to_string_lossy(),
        });
        let input = request(&workspace.to_string_lossy(), payload);
        let bytes = evaluate_package_review_plan(&input).expect("request must encode a result");
        serde_json::from_slice::<Value>(&bytes).expect("result")["payload"].clone()
    };
    let proven = answer("npm install zod --ignore-scripts --allow-git=none");
    assert_eq!(
        proven["artifact"]["metadata"]["verified_npm_version"],
        "11.9.0"
    );
    assert_eq!(proven["may_allow"], true);
    // `tail` is not on the stamped `PATH`, so the filter cannot be placed
    // outside the workspace and only a block verdict applies.
    let piped = answer("npm install zod --ignore-scripts --allow-git=none | tail -3");
    assert!(piped["artifact"].is_object());
    assert!(piped["artifact"]["metadata"]
        .get("verified_npm_version")
        .is_none());
    assert_eq!(piped["may_allow"], false);
    // A saved package approval stands for the whole command only when every
    // filter runs from outside the workspace.
    assert_eq!(proven["keyed"], true);
    assert_eq!(piped["keyed"], false);
    executable(&bin.join("tail"));
    assert_eq!(answer("npm ci --ignore-scripts | tail -3")["keyed"], true);
    let owned = workspace.join("bin");
    fs::create_dir_all(&owned).expect("workspace bin");
    executable(&owned.join("tail"));
    let mut payload = shell("npm ci --ignore-scripts | tail -3");
    payload["guard_execution_environment"] = json!({
        "environment_names": ["PATH", "HOME"],
        "path": format!("{}:{}", owned.to_string_lossy(), bin.to_string_lossy()),
        "home": root.path().to_string_lossy(),
    });
    let input = request(&workspace.to_string_lossy(), payload);
    let bytes = evaluate_package_review_plan(&input).expect("request must encode a result");
    let shadowed = serde_json::from_slice::<Value>(&bytes).expect("result")["payload"].clone();
    assert!(shadowed["artifact"].is_object());
    assert_eq!(shadowed["keyed"], false);
    // The key is derived from the stamped PATH and HOME alone, so an exported
    // npm setting, whose value the stamp withholds, leaves the install unkeyed.
    let mut payload = shell("npm ci --ignore-scripts");
    payload["guard_execution_environment"] = json!({
        "environment_names": ["PATH", "HOME", "npm_config_registry"],
        "path": bin.to_string_lossy(),
        "home": root.path().to_string_lossy(),
    });
    let input = request(&workspace.to_string_lossy(), payload);
    let bytes = evaluate_package_review_plan(&input).expect("request must encode a result");
    let configured = serde_json::from_slice::<Value>(&bytes).expect("result")["payload"].clone();
    assert!(configured["artifact"].is_object());
    assert_eq!(configured["keyed"], false);
    // An inert `NODE_OPTIONS`, such as an agent wrapper's heap size, and an
    // inert npm setting keep the key; a `NODE_OPTIONS` the hook did not see
    // as inert does not.
    let keyed_with = |names: Value, inert: bool| {
        let mut payload = shell("npm ci --ignore-scripts");
        payload["guard_execution_environment"] = json!({
            "environment_names": names,
            "path": bin.to_string_lossy(),
            "home": root.path().to_string_lossy(),
            "node_options_inert": inert,
        });
        let input = request(&workspace.to_string_lossy(), payload);
        let bytes = evaluate_package_review_plan(&input).expect("request must encode a result");
        serde_json::from_slice::<Value>(&bytes).expect("result")["payload"]["keyed"].clone()
    };
    let wrapped = json!(["PATH", "HOME", "NODE_OPTIONS", "npm_config_cache"]);
    assert_eq!(keyed_with(wrapped.clone(), true), true);
    assert_eq!(keyed_with(wrapped, false), false);
}

const SAFE_FLAGS: &str = "--ignore-scripts --allow-git=none";

fn shape(command: &str) -> Option<super::ReviewShape> {
    super::review_shape(shell(command).as_object().expect("payload is a map"))
}

#[test]
fn output_filters_after_an_install_are_planned_without_them() {
    for (suffix, programs) in [
        ("2>&1", vec![]),
        ("2>&1 | tail -3", vec!["tail"]),
        ("| tail -n 5", vec!["tail"]),
        ("2>&1|grep -i added", vec!["grep"]),
        ("| head -20 | tail -n3", vec!["head", "tail"]),
        ("| tail -3 | tail -1", vec!["tail"]),
    ] {
        let planned = shape(&format!("npm install zod {SAFE_FLAGS} {suffix}")).expect(suffix);
        assert_eq!(
            planned.tokens,
            [
                "npm",
                "install",
                "zod",
                "--ignore-scripts",
                "--allow-git=none"
            ],
            "{suffix}"
        );
        assert_eq!(planned.filter_programs, programs, "{suffix}");
    }
}

#[test]
fn other_trailing_commands_plan_nothing() {
    for suffix in [
        "| grep -f/etc/passwd",
        "| grep x /etc/passwd",
        "| tail /etc/passwd",
        "| tail -f log",
        "| tee log",
        "| sh",
        "> out.txt",
        "2>&1 | tail -3 > out.txt",
        "&& tail -3",
    ] {
        assert_eq!(
            shape(&format!("npm install zod {SAFE_FLAGS} {suffix}")),
            None,
            "{suffix}"
        );
    }
    for command in [
        format!("FOO=1 npm install zod {SAFE_FLAGS}"),
        format!("npm install ~/zod {SAFE_FLAGS}"),
    ] {
        assert_eq!(shape(&command), None, "{command}");
    }
}

/// The managed safety guide names this install as the one that continues, so
/// it must reach the evaluator token for token. Codex ran a bare
/// `npm install` for a Vite game, which runs install scripts and is rightly
/// reviewed. The `npm ci` form the guide also names is proven by the lockfile
/// install tests.
#[test]
fn the_safety_guide_install_reaches_the_evaluator() {
    let guide = include_str!("agent_safety_guidance.md");
    let guide = guide.split_whitespace().collect::<Vec<_>>().join(" ");
    let command = "npm install --ignore-scripts";
    assert!(guide.contains(&format!("`{command}`")));
    assert_eq!(
        shape(command).expect("a plain install").tokens,
        ["npm", "install", "--ignore-scripts"]
    );
    let answer = plan(shell(command));
    assert_eq!(answer["artifact"]["metadata"]["intent_kind"], "install");
}

fn planned_in(workspace: &std::path::Path, command: &str, environment: Option<Value>) -> Value {
    let mut payload = shell(command);
    if let Some(environment) = environment {
        payload["guard_execution_environment"] = environment;
    }
    let input = request(&workspace.to_string_lossy(), payload);
    let bytes = evaluate_package_review_plan(&input).expect("request must encode a result");
    serde_json::from_slice::<Value>(&bytes).expect("result")["payload"].clone()
}

/// Agents run an install from a nested checkout with `cd linked && npm ci`.
/// The plan reads it in the directory the `cd` reaches and names that
/// directory, so the evaluator keys the install by the checkout it runs in.
#[test]
fn a_leading_cd_into_the_workspace_moves_the_plan() {
    let root = tempfile::tempdir().expect("workspace");
    let workspace = root.path();
    std::fs::create_dir_all(workspace.join("linked")).expect("linked");
    std::fs::create_dir_all(workspace.join(".cache")).expect("hidden");
    for checkout in [workspace.to_path_buf(), workspace.join("linked")] {
        std::fs::write(
            checkout.join("package.json"),
            json!({"name": "app", "version": "1.0.0"}).to_string(),
        )
        .expect("manifest");
        std::fs::write(
            checkout.join("package-lock.json"),
            json!({"name": "app", "version": "1.0.0", "lockfileVersion": 3, "packages": {"": {"name": "app", "version": "1.0.0"}}}).to_string(),
        )
        .expect("lockfile");
    }
    let linked = workspace
        .join("linked")
        .canonicalize()
        .expect("canonical linked");
    #[cfg(unix)]
    std::os::unix::fs::symlink(workspace.join("linked"), workspace.join("alias")).expect("alias");
    let declared = json!({"environment_names": ["PATH", "HOME"], "path": "/usr/bin"});
    let with_cdpath = json!({"environment_names": ["PATH", "CDPATH"], "path": "/usr/bin"});

    let plain = planned_in(workspace, "npm ci --ignore-scripts", None);
    assert_eq!(plain["artifact"]["metadata"]["intent_kind"], "sync");
    assert_eq!(plain["may_allow"], false);
    assert_eq!(plain["workspace"], Value::Null);

    for command in [
        "cd ./linked && npm ci --ignore-scripts",
        "cd linked/ && npm ci --ignore-scripts",
    ] {
        let moved = planned_in(workspace, command, Some(declared.clone()));
        assert!(moved["artifact"].is_object(), "{command}");
        assert_eq!(
            moved["workspace"],
            json!(linked.to_string_lossy()),
            "{command}"
        );
        assert_eq!(
            moved["artifact"]["metadata"]["redacted_command"], "npm ci --ignore-scripts",
            "{command}"
        );
    }
    let absolute = format!("cd {} && npm ci --ignore-scripts", linked.to_string_lossy());
    assert_eq!(
        planned_in(workspace, &absolute, None)["workspace"],
        json!(linked.to_string_lossy())
    );

    // A searched name needs a declared environment without `CDPATH`, and
    // `.cache` is a searched name.
    for (command, environment) in [
        ("cd linked && npm ci --ignore-scripts", None),
        (
            "cd linked && npm ci --ignore-scripts",
            Some(with_cdpath.clone()),
        ),
        ("cd .cache && npm ci --ignore-scripts", Some(with_cdpath)),
    ] {
        let refused = planned_in(workspace, command, environment);
        assert_eq!(refused["artifact"], Value::Null, "{command}");
        assert_eq!(refused["workspace"], Value::Null, "{command}");
    }
    assert!(planned_in(
        workspace,
        "cd linked && npm ci --ignore-scripts",
        Some(declared.clone())
    )["artifact"]
        .is_object());

    // Outside the workspace, missing, or not a lone `cd`: nothing is planned.
    for command in [
        "cd .. && npm ci --ignore-scripts",
        "cd /tmp && npm ci --ignore-scripts",
        "cd ./missing && npm ci --ignore-scripts",
        "cd -P ./linked && npm ci --ignore-scripts",
        "cd ./linked; npm ci --ignore-scripts",
        "cd ./linked && cd .. && npm ci --ignore-scripts",
        // A shell's `cd` drops `..` as text; through a symlink that lands
        // somewhere other than the resolved path, so `..` is never read.
        "cd ./linked/../linked && npm ci --ignore-scripts",
        "cd ./alias/.. && npm ci --ignore-scripts",
    ] {
        assert_eq!(
            planned_in(workspace, command, Some(declared.clone()))["artifact"],
            Value::Null,
            "{command}"
        );
    }
}
