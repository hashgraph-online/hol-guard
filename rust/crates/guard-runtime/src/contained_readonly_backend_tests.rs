use super::*;

#[cfg(target_os = "linux")]
fn denial(route: Route) -> Value {
    json!({
        "decision": "deny",
        "policy_action": "sandbox-required",
        "reason_code": route.0,
        "required_execution_profile": route.1,
    })
}

#[cfg(target_os = "linux")]
fn call(command: &str) -> Map<String, Value> {
    let Value::Object(call) = json!({ "command": command }) else {
        unreachable!()
    };
    call
}

#[cfg(target_os = "macos")]
#[test]
fn seatbelt_runs_every_read_only_route() {
    assert!(ROUTES.into_iter().all(host_runs));
}

#[cfg(target_os = "linux")]
#[test]
fn bubblewrap_runs_only_the_python_routes() {
    let runs: Vec<&str> = ROUTES
        .into_iter()
        .filter(|route| host_runs(*route))
        .map(|(_, profile)| profile)
        .collect();
    assert_eq!(runs, [PYTHON_EVAL_PROFILE, GIT_PROFILE, PYTEST_PROFILE]);
}

#[cfg(target_os = "linux")]
#[test]
fn a_node_run_keeps_guards_own_sink_on_linux() {
    let python = denial(ROUTES[0]);
    let node = denial(ROUTES[1]);
    assert!(readonly_shape(&python, &call("python3 -c 0")));
    assert!(readonly_shape(&denial(ROUTES[5]), &call("git log -1")));
    assert!(!readonly_shape(&node, &call("node -e 0")));
    assert!(!readonly_shape(&denial(VITEST_ROUTE), &call("vitest run")));
}
