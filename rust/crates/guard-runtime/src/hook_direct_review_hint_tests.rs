use super::*;
use serde_json::json;

const DOCKER: &str = "docker version --format '{{.Server.Version}}'";
const DOCKER_PERMISSION: &str = "command.container-runtime.permission.docker-sensitive";

fn admitted_controls(name: &str) -> CompiledNativeCommandControls {
    let home = std::env::temp_dir().join(format!(
        "guard-direct-review-hint-{name}-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&home).unwrap();
    let home = home.canonicalize().unwrap();
    crate::contributed_mcp_catalog_test_support::controls_for(&home, false, &[], &[])
}

fn review(command: &str) -> PreToolRequestV1 {
    PreToolRequestV1 {
        model: CommandModelRequestV1 {
            command: command.into(),
            dialect: "posix".into(),
            transport: "shell_string".into(),
            extraction_provenance: "guard-shell".into(),
        },
        cwd: None,
        home_dir: None,
        execution_environment: None,
        extension_evidence: true,
    }
}

/// The result the hook paused on: the same evaluation the hint repeats.
fn paused(controls: &CompiledNativeCommandControls, command: &str) -> Object {
    let result =
        crate::pre_tool_extension_evidence_op::evidence_response(&review(command), Some(controls))
            .unwrap();
    assert_eq!(result["minimum_action"], "review", "{command}");
    assert_eq!(result["reason_code"], "native_command_review_required");
    result.as_object().cloned().unwrap()
}

fn soon() -> Instant {
    Instant::now() + Duration::from_secs(5)
}

#[test]
fn the_review_that_paused_gets_its_allow_hint() {
    let controls = admitted_controls("paused");
    let result = paused(&controls, DOCKER);
    let hint = hint_under(&controls, &review(DOCKER), &result, soon())
        .unwrap()
        .expect("a docker-sensitive review has a hint");
    assert_eq!(hint.permission_ids, [DOCKER_PERMISSION]);
    assert_eq!(hint.extension_ids, ["command.container-runtime"]);
}

#[test]
fn a_review_on_other_evidence_has_no_hint() {
    let controls = admitted_controls("other");
    let result = paused(&controls, DOCKER);
    for (key, value) in [
        ("observations_digest", json!("0".repeat(64))),
        ("control_effective_digest", json!("0".repeat(64))),
        ("observations_digest", Value::Null),
    ] {
        let mut moved = result.clone();
        moved["command_extensions"]["binding"][key] = value;
        assert!(
            !same_review(&moved, &Value::Object(result.clone())),
            "{key}"
        );
        assert_eq!(
            hint_under(&controls, &review(DOCKER), &moved, soon()).unwrap(),
            None,
            "{key}"
        );
    }
    for (key, value) in [
        ("minimum_action", json!("require-reapproval")),
        ("reason_code", json!("native_command_sensitive_access")),
    ] {
        let mut moved = result.clone();
        moved.insert(key.to_owned(), value);
        assert_eq!(
            hint_under(&controls, &review(DOCKER), &moved, soon()).unwrap(),
            None,
            "{key}"
        );
    }
    let mut unbound = result.clone();
    unbound.remove("command_extensions");
    assert!(!same_review(&unbound, &Value::Object(result)));
}

#[test]
fn a_spent_deadline_has_no_hint() {
    let controls = admitted_controls("spent");
    let result = paused(&controls, DOCKER);
    let spent = Instant::now() + SAFETY_MARGIN;
    assert_eq!(
        hint_under(&controls, &review(DOCKER), &result, spent).unwrap(),
        None
    );
    assert_eq!(remaining(Instant::now()), None);
}

#[test]
fn the_reduction_budget_keeps_the_daemons_slack() {
    let budget = |millis| reduction_budget(Duration::from_millis(millis)).as_millis();
    assert_eq!(budget(10_000), 3_000);
    assert_eq!(budget(3_000), 1_500);
    assert_eq!(budget(400), 200);
}

#[test]
fn without_a_scope_the_review_keeps_its_coverage() {
    let controls = admitted_controls("coverage");
    let result = paused(&controls, DOCKER);
    let payload = json!({"tool_name": "Bash", "tool_input": {"command": DOCKER}});
    let payload = payload.as_object().unwrap();
    let hint = coverage_hint(&result);
    assert_eq!(hint["schema"], "guard.extension-coverage-hint.v1");
    assert_eq!(
        hint["segments"][0]["extension_ids"],
        json!(["command.container-runtime"])
    );
    let request = json!({"extension_allow_hint": hint});
    assert_eq!(
        settled(None, payload, "/", "", &result, request.clone()),
        request
    );
    let mut unobserved = result;
    unobserved.remove("command_extensions");
    assert_eq!(coverage_hint(&unobserved), Value::Null);
}
