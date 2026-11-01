use super::*;

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn denial(route: Route) -> Value {
    json!({
        "decision": "deny",
        "policy_action": "sandbox-required",
        "reason_code": route.0,
        "required_execution_profile": route.1,
    })
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn call(command: &str) -> Map<String, Value> {
    let Value::Object(call) = json!({ "command": command }) else {
        unreachable!()
    };
    call
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn every_read_only_route_takes_the_native_sink_on_a_sandboxed_host() {
    assert!(readonly_shape(
        &denial(ROUTES[0]),
        &call("python3 -c 0"),
        "/w",
        "/h"
    ));
    assert!(readonly_shape(
        &denial(ROUTES[5]),
        &call("git log -1"),
        "/w",
        "/h"
    ));
    assert!(readonly_shape(
        &denial(ROUTES[1]),
        &call("node -e 0"),
        "/w",
        "/h"
    ));
    assert!(readonly_shape(
        &denial(ROUTES[4]),
        &call("node --test"),
        "/w",
        "/h"
    ));
    assert!(readonly_shape(
        &denial(VITEST_ROUTE),
        &call("vitest run"),
        "/w",
        "/h"
    ));
}

fn plan(backend: &str, profile: &str) -> ReadonlyPlan {
    serde_json::from_value(json!({
        "profile_version": profile,
        "backend": backend,
        "backend_executable": "/usr/bin/bwrap",
        "workspace": "/work",
        "cwd": "/work",
        "executable": "/usr/bin/node",
        "command": ["/usr/bin/node", "-e", "0"],
        "allowed_executables": ["/usr/bin/node"],
        "denied_capabilities": [],
    }))
    .unwrap()
}

#[test]
fn only_a_node_run_under_bubblewrap_takes_nodes_memory_bounds() {
    for profile in [
        NODE_EVAL_PROFILE,
        VITEST_PROFILE,
        NODE_TEST_PROFILE,
        NODE_TOOL_PROFILE,
        NODE_BUILD_PROFILE,
    ] {
        assert!(node_memory(&plan(BUBBLEWRAP, profile)), "{profile}");
        assert!(!node_memory(&plan(SEATBELT, profile)), "{profile}");
    }
    for profile in [PYTHON_EVAL_PROFILE, GIT_PROFILE, PYTEST_PROFILE] {
        assert!(!node_memory(&plan(BUBBLEWRAP, profile)), "{profile}");
    }
}
