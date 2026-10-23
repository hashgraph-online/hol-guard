//! The deadline a client waits on, and the ceilings that bound it.

use super::*;

#[test]
fn a_contained_workspace_write_keeps_its_callers_deadline() {
    // `try_execute_contained_workspace_write` allows the write two minutes,
    // and the shipped default already asks for ten seconds. Clamping either to
    // the nine-second ceiling abandons the reply of a write that is still
    // running, so the caller reports the runtime as unavailable while the
    // resident is in fact finishing the job.
    assert_eq!(
        client_timeout(
            br#"{"operation":"contained_workspace_write_execute","deadline_budget_ms":120000}"#
        ),
        Duration::from_secs(120)
    );
    assert_eq!(
        client_timeout(
            br#"{"operation":"contained_workspace_write_execute","deadline_budget_ms":10000}"#
        ),
        Duration::from_secs(10)
    );
    // It shares the contained runners' ceiling, which still bounds the wait.
    assert_eq!(
        client_timeout(
            br#"{"operation":"contained_workspace_write_execute","deadline_budget_ms":999999999}"#
        ),
        Duration::from_millis(670_000)
    );
}

#[test]
fn a_contained_execute_keeps_the_deadline_its_own_timeout_earns() {
    // The Python client sends the request's own timeout plus thirty seconds of
    // transport slack. A contained run permitted to take a minute must not be
    // abandoned at the nine-second default.
    assert_eq!(
        client_timeout(br#"{"operation":"contained_execute","deadline_budget_ms":90000}"#),
        Duration::from_secs(90)
    );
    // The containment contract bounds a request at one hour, so the ceiling
    // covers that plus the client's slack and nothing beyond it.
    assert_eq!(
        client_timeout(br#"{"operation":"contained_execute","deadline_budget_ms":3630000}"#),
        Duration::from_millis(3_630_000)
    );
    assert_eq!(
        client_timeout(br#"{"operation":"contained_execute","deadline_budget_ms":9999999}"#),
        Duration::from_millis(3_630_000)
    );
}

#[test]
fn an_extension_control_preview_keeps_the_deadline_python_grants_it() {
    // Python asks fifteen seconds for a semantic preview and five for a plain
    // composition or resolution; the ceiling must not cut the former to nine.
    assert_eq!(
        client_timeout(br#"{"operation":"extension_control","deadline_budget_ms":15000}"#),
        Duration::from_secs(15)
    );
    assert_eq!(
        client_timeout(br#"{"operation":"extension_control","deadline_budget_ms":5000}"#),
        Duration::from_secs(5)
    );
    // The ceiling still bounds a larger ask.
    assert_eq!(
        client_timeout(br#"{"operation":"extension_control","deadline_budget_ms":999999}"#),
        Duration::from_secs(15)
    );
}

#[test]
fn client_deadline_is_bounded() {
    assert_eq!(
        client_timeout(br#"{"deadline_budget_ms":999999}"#),
        Duration::from_secs(9)
    );
    assert_eq!(client_timeout(br#"{}"#), Duration::from_millis(750));
    assert_eq!(
        client_timeout(br#"{"operation":"skill_directory_identity","deadline_budget_ms":60000}"#),
        Duration::from_secs(60)
    );
    assert_eq!(
        client_timeout(br#"{"operation":"skill_directory_identity","deadline_budget_ms":999999}"#),
        Duration::from_secs(60)
    );
    assert_eq!(
        client_timeout(br#"{"operation":"prompt_analyze","deadline_budget_ms":60000}"#),
        Duration::from_secs(9)
    );
    assert_eq!(
        client_timeout(br#"{"operation":"daemon_lifecycle_decide","deadline_budget_ms":30000}"#),
        Duration::from_secs(30)
    );
    assert_eq!(
        client_timeout(br#"{"operation":"daemon_lifecycle_decide","deadline_budget_ms":999999}"#),
        Duration::from_secs(30)
    );
    assert_eq!(
        client_timeout(br#"{"operation":"daemon_lifecycle_decide","deadline_budget_ms":9000}"#),
        Duration::from_secs(9)
    );
    for operation in [
        "contained_node_execute",
        "contained_typescript_execute",
        "contained_package_script_execute",
        "shim_admin",
    ] {
        let payload = format!(r#"{{"operation":"{operation}","deadline_budget_ms":130000}}"#);
        assert_eq!(client_timeout(payload.as_bytes()), Duration::from_secs(130));
        let payload = format!(r#"{{"operation":"{operation}","deadline_budget_ms":9999999}}"#);
        assert_eq!(client_timeout(payload.as_bytes()), Duration::from_secs(670));
    }
    assert_eq!(
        client_timeout(br#"{"operation":"codex_request_resume","deadline_budget_ms":10000}"#),
        Duration::from_secs(10)
    );
    assert_eq!(
        client_timeout(br#"{"operation":"codex_request_resume","deadline_budget_ms":65000}"#),
        Duration::from_secs(65)
    );
    assert_eq!(
        client_timeout(br#"{"operation":"codex_request_resume","deadline_budget_ms":999999}"#),
        Duration::from_secs(75)
    );
    assert_eq!(
        client_timeout(br#"{"operation":"guard_store","deadline_budget_ms":30000}"#),
        Duration::from_secs(30)
    );
    assert_eq!(
        client_timeout(br#"{"operation":"guard_store","deadline_budget_ms":9999999}"#),
        Duration::from_secs(605)
    );
    assert_eq!(
        client_timeout(br#"{"deadline_budget_ms":250}"#),
        Duration::from_millis(250)
    );
}
