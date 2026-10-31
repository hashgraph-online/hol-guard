use super::*;

fn words(command: &[&str]) -> Vec<String> {
    command.iter().map(|word| (*word).to_owned()).collect()
}

fn response(reason: &str, profile: &str) -> Map<String, Value> {
    let Value::Object(response) = json!({
        "decision": "deny",
        "policy_action": "sandbox-required",
        "reason_code": reason,
        "required_execution_profile": profile,
    }) else {
        unreachable!()
    };
    response
}

fn call(command: &str) -> Map<String, Value> {
    let Value::Object(call) = json!({ "command": command }) else {
        unreachable!()
    };
    call
}

fn plan(profile: &str) -> ReadonlyPlan {
    ReadonlyPlan {
        profile_version: profile.to_owned(),
        backend: SEATBELT.to_owned(),
        backend_executable: "/usr/bin/sandbox-exec".to_owned(),
        workspace: "/w".to_owned(),
        cwd: "/w".to_owned(),
        executable: "/usr/bin/node".to_owned(),
        command: words(&["node", "-e", "0"]),
        allowed_executables: words(&["/usr/bin/node"]),
        read_only_roots: Vec::new(),
        output_roots: Vec::new(),
        denied_capabilities: Vec::new(),
        user_site_root: None,
        settings: Vec::new(),
    }
}

#[test]
fn only_a_live_read_only_denial_names_a_route() {
    for (reason, profile) in ROUTES {
        assert_eq!(
            readonly_route(&response(reason, profile)),
            Some((reason, profile))
        );
    }
    let python = ROUTES[0];
    let mut observed = response(python.0, python.1);
    observed.insert("observe_mode".into(), Value::Bool(true));
    let mut allowed = response(python.0, python.1);
    allowed.insert("decision".into(), json!("allow"));
    let mut asked = response(python.0, python.1);
    asked.insert("policy_action".into(), json!("require-reapproval"));
    for refused in [
        observed,
        allowed,
        asked,
        response(python.0, NODE_EVAL_PROFILE),
        response("native_workspace_containment_required", python.1),
    ] {
        assert_eq!(readonly_route(&refused), None, "{refused:?}");
    }
}

#[test]
fn a_plain_evaluation_is_the_program_and_its_clock() {
    assert_eq!(
        plain_program("python3 -c 'print(1)'"),
        Some((words(&["python3", "-c", "print(1)"]), None, Kind::Eval))
    );
    assert_eq!(
        plain_program("node -e 'console.log(1)'"),
        Some((words(&["node", "-e", "console.log(1)"]), None, Kind::Eval))
    );
    assert_eq!(
        plain_program("timeout 20 python3 -c 0"),
        Some((words(&["python3", "-c", "0"]), Some(20), Kind::Eval))
    );
}

#[test]
fn a_setting_or_directory_change_is_not_the_plain_shape() {
    for command in [
        "CI=1 python3 -c 0",
        "cd x && python3 -c 0",
        "python3 -c 'unterminated",
        "CI=1 npx eslint .",
        "CI=1 vitest run",
    ] {
        assert_eq!(plain_program(command), None, "{command}");
    }
}

#[test]
fn the_edge_routes_only_a_plain_evaluation_without_a_cwd_argument() {
    let (reason, profile) = ROUTES[0];
    let denial = Value::Object(response(reason, profile));
    assert!(plain_call(&denial, &call("python3 -c 0")));
    let mut anchored = call("python3 -c 0");
    anchored.insert("cwd".into(), json!("/w/sub"));
    assert!(!plain_call(&denial, &anchored));
    // Settings in front are carried; the run behind them must still be of
    // the route's kind.
    assert!(plain_call(&denial, &call("CI=1 python3 -c 0")));
    assert!(plain_call(&denial, &call("REPORT_DIR=out python3 -c 0")));
    assert!(!plain_call(&denial, &call("CI=1 vitest run")));
    assert!(!plain_call(&denial, &call("CI=1 cd x && python3 -c 0")));
    assert!(!plain_call(&denial, &Map::new()));
    let workspace = Value::Object(response("native_workspace_containment_required", profile));
    assert!(!plain_call(&workspace, &call("python3 -c 0")));
}

#[test]
fn a_node_evaluation_bun_runs_carries_buns_reason() {
    let node = plan(NODE_EVAL_PROFILE);
    assert_eq!(
        reason_for(&node, &words(&["/opt/bin/bun", "-e", "0"])),
        ROUTES[2].0
    );
    assert_eq!(reason_for(&node, &words(&["node", "-e", "0"])), ROUTES[1].0);
    assert_eq!(
        reason_for(&plan(PYTHON_EVAL_PROFILE), &words(&["python3", "-c", "0"])),
        ROUTES[0].0
    );
}

#[test]
fn a_plain_vitest_run_is_the_runner_and_its_clock() {
    assert_eq!(
        plain_program("vitest run"),
        Some((words(&["vitest", "run"]), None, Kind::Vitest))
    );
    assert_eq!(
        plain_program("timeout 60 npx vitest run src"),
        Some((
            words(&["npx", "vitest", "run", "src"]),
            Some(60),
            Kind::Vitest
        ))
    );
}

#[test]
fn a_plain_node_test_run_or_git_inspection_is_its_own_kind() {
    assert_eq!(
        plain_program("node --test"),
        Some((words(&["node", "--test"]), None, Kind::NodeTest))
    );
    assert_eq!(
        plain_program("git status --short"),
        Some((words(&["git", "status", "--short"]), None, Kind::Git))
    );
    assert_eq!(Kind::of(ROUTES[4]), Kind::NodeTest);
    assert_eq!(Kind::of(ROUTES[5]), Kind::Git);
    let git = Value::Object(response(ROUTES[5].0, ROUTES[5].1));
    assert!(plain_call(&git, &call("git log -1")));
    assert!(!plain_call(&git, &call("node --test")));
}

#[test]
fn any_other_plain_program_is_planned_as_pytest() {
    assert_eq!(
        plain_program("pytest -q"),
        Some((words(&["pytest", "-q"]), None, Kind::Pytest))
    );
    assert_eq!(
        plain_program("timeout 30 pytest tests"),
        Some((words(&["pytest", "tests"]), Some(30), Kind::Pytest))
    );
    assert_eq!(Kind::of(ROUTES[6]), Kind::Pytest);
    let pytest = Value::Object(response(ROUTES[6].0, ROUTES[6].1));
    assert!(plain_call(&pytest, &call("pytest -q")));
    assert!(!plain_call(&pytest, &call("python3 -c 0")));
    assert!(!plain_call(&pytest, &call("cd x && pytest -q")));
    assert!(!plain_call(&pytest, &call("pytest -q > report.txt")));
}

#[test]
fn a_plain_lint_typecheck_or_build_run_is_a_node_tool() {
    assert_eq!(
        plain_program("npx eslint ."),
        Some((words(&["npx", "eslint", "."]), None, Kind::NodeTool))
    );
    assert_eq!(Kind::of(ROUTES[7]), Kind::NodeTool);
    let tool = Value::Object(response(ROUTES[7].0, ROUTES[7].1));
    assert!(plain_call(&tool, &call("npx eslint .")));
    assert!(!plain_call(&tool, &call("vitest run")));
    // A build is the same tool, planned with the one directory it writes.
    assert_eq!(
        ROUTES[8],
        (
            "native_node_build_output_containment_required",
            NODE_BUILD_PROFILE
        )
    );
    assert_eq!(Kind::of(ROUTES[8]), Kind::NodeTool);
    let build = Value::Object(response(ROUTES[8].0, ROUTES[8].1));
    assert!(plain_call(&build, &call("npx vite build")));
    assert!(plain_call(&build, &call("CI=1 npx vite build")));
}

#[test]
fn a_package_test_is_routed_by_the_package_route() {
    assert_eq!(
        ROUTES[9],
        (
            "native_package_test_readonly_containment_required",
            PACKAGE_PROFILE
        )
    );
    assert_eq!(Kind::of(ROUTES[9]), Kind::Package);
    let package = Value::Object(response(ROUTES[9].0, ROUTES[9].1));
    assert!(plain_call(&package, &call("npm test")));
    assert!(plain_call(&package, &call("CI=1 npm test")));
    assert!(!plain_call(&package, &call("node --test")));
}

#[test]
fn the_edge_routes_a_call_only_to_the_sink_of_its_own_kind() {
    let vitest = Value::Object(response(VITEST_ROUTE.0, VITEST_ROUTE.1));
    assert!(plain_call(&vitest, &call("vitest run")));
    assert!(!plain_call(&vitest, &call("python3 -c 0")));
    let (reason, profile) = ROUTES[1];
    let node = Value::Object(response(reason, profile));
    assert!(plain_call(&node, &call("node -e 0")));
    assert!(!plain_call(&node, &call("vitest run")));
    assert_eq!(Kind::of(VITEST_ROUTE), Kind::Vitest);
    assert_eq!(Kind::of(ROUTES[0]), Kind::Eval);
}

#[test]
fn a_denied_write_is_named_in_any_case_on_either_stream() {
    assert!(names_denied_write(&[b"", b"Error: EROFS: read-only"]));
    assert!(names_denied_write(&[b"Operation not permitted", b""]));
    assert!(names_denied_write(&[b"x", b"EPERM: open 'report.xml'"]));
    assert!(!names_denied_write(&[b"1 failed", b"AssertionError"]));
    assert!(!names_denied_write(&[
        b"checks filePermissions",
        b"STEPERMIT"
    ]));
    assert!(!names_denied_write(&[b"skip_erofs_test passed"]));
}
