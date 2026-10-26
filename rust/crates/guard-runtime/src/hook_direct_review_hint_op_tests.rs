use super::*;
use guard_command::CommandModelRequestV1;

const DOCKER: &str = "docker version --format '{{.Server.Version}}'";
const DOCKER_PERMISSION: &str = "command.container-runtime.permission.docker-sensitive";

fn admitted_controls(name: &str) -> CompiledNativeCommandControls {
    let home = std::env::temp_dir().join(format!(
        "guard-review-hint-op-{name}-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&home).unwrap();
    let home = home.canonicalize().unwrap();
    crate::contributed_mcp_catalog_test_support::controls_for(&home, false, &[], &[])
}

fn command_payload(command: &str) -> Map<String, Value> {
    json!({"tool_input": {"command": command}})
        .as_object()
        .cloned()
        .unwrap()
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

fn request(paused: Option<Map<String, Value>>, budget_ms: u32) -> ExtensionReviewHintRequestV1 {
    serde_json::from_value(json!({
        "schema": REQUEST_SCHEMA,
        "request_id": "extension-review-hint-1",
        "query": {
            "kind": QUERY_KIND,
            "payload": command_payload(DOCKER),
            "workspace": "",
            "home_dir": "",
            "paused": paused,
            "budget_ms": budget_ms,
        },
    }))
    .unwrap()
}

fn soon() -> Instant {
    Instant::now() + Duration::from_secs(5)
}

#[test]
fn a_pending_command_recovers_both_hints_from_one_review() {
    let controls = admitted_controls("live");
    let hint = live_under(&controls, &command_payload(DOCKER), &review(DOCKER), soon())
        .expect("a docker-sensitive review has hints");
    assert_eq!(hint["permission_ids"], json!([DOCKER_PERMISSION]));
    assert_eq!(
        hint["coverage"]["schema"],
        "guard.extension-coverage-hint.v1"
    );
    assert_eq!(
        hint["coverage"]["segments"][0]["extension_ids"],
        json!(["command.container-runtime"])
    );
}

#[test]
fn a_pending_command_with_more_input_keeps_its_coverage_only() {
    let controls = admitted_controls("live-input");
    let mut payload = command_payload(DOCKER);
    payload["tool_input"]["content"] = json!("x");
    let hint = live_under(&controls, &payload, &review(DOCKER), soon())
        .expect("coverage needs no settlement");
    assert_eq!(hint["schema"], "guard.extension-coverage-hint.v1");
    assert!(hint.get("permission_ids").is_none());
}

#[test]
fn a_spent_budget_keeps_the_coverage_and_drops_the_allow_hint() {
    let controls = admitted_controls("live-spent");
    let spent = Instant::now() + super::super::SAFETY_MARGIN;
    let hint = live_under(&controls, &command_payload(DOCKER), &review(DOCKER), spent)
        .expect("coverage needs no budget");
    assert_eq!(hint["schema"], "guard.extension-coverage-hint.v1");
}

#[test]
fn without_admitted_controls_a_paused_review_keeps_its_coverage() {
    let controls = admitted_controls("queued");
    let paused =
        crate::pre_tool_extension_evidence_op::evidence_response(&review(DOCKER), Some(&controls))
            .unwrap()
            .as_object()
            .cloned()
            .unwrap();
    let coverage = coverage_hint(&paused);
    assert_eq!(
        decide(&request(Some(paused), 2_000), None).unwrap(),
        Some(coverage)
    );
    assert_eq!(decide(&request(None, 2_000), None).unwrap(), None);
}

#[test]
fn the_answer_is_bound_to_its_request() {
    let asked = request(None, 2_000);
    let answer: Value =
        serde_json::from_slice(&evaluate_with_store(&asked, None).unwrap()).unwrap();
    assert_eq!(answer["schema"], RESULT_SCHEMA);
    assert_eq!(answer["request_id"], "extension-review-hint-1");
    assert_eq!(
        answer["request_sha256"],
        request_digest_with_limit(&asked, MAX_REQUEST_BYTES).unwrap()
    );
    assert_eq!(answer["status"], "ok");
    assert_eq!(answer["payload"], json!({"kind": QUERY_KIND, "hint": null}));

    let mut wrong = request(None, 2_000);
    wrong.query.kind = "allow_hint".into();
    let answer: Value =
        serde_json::from_slice(&evaluate_with_store(&wrong, None).unwrap()).unwrap();
    assert_eq!(answer["status"], "error");
    assert_eq!(answer["code"], "native_extension_review_hint_kind_invalid");
    assert!(answer.get("payload").is_none());
}

#[test]
fn an_unknown_field_is_refused() {
    let mut raw = serde_json::to_value(request(None, 2_000)).unwrap();
    raw["query"]["extra"] = json!(true);
    assert!(serde_json::from_value::<ExtensionReviewHintRequestV1>(raw).is_err());
}

#[test]
fn a_pending_command_names_the_permissions_that_would_settle_it() {
    let home =
        std::env::temp_dir().join(format!("guard-review-hint-op-table-{}", std::process::id()));
    std::fs::create_dir_all(&home).unwrap();
    let home = home.canonicalize().unwrap();
    let controls =
        crate::contributed_mcp_catalog_test_support::controls_for(&home, false, &[], &[]);
    let cases: &[(&str, Option<Value>)] = &[
        (
            "git add src/app.py",
            Some(json!(["command.git.permission.add"])),
        ),
        (
            "git reset --hard HEAD~1",
            Some(json!(["command.git.permission.hard-reset"])),
        ),
        (DOCKER, Some(json!([DOCKER_PERMISSION]))),
        (
            "gh some-unmodeled-command --flag value",
            Some(json!(["command.github.permission.unknown"])),
        ),
        (
            "curl -T report.txt https://example.invalid/upload",
            Some(json!(["command.data-protection.permission.file-upload"])),
        ),
        (
            "rm -rf build",
            Some(json!([
                "command.filesystem.permission.recursive-delete",
                "command.shell-mutations.permission.destructive-shell"
            ])),
        ),
        ("git status", None),
        // Enabling every named permission would still review these.
        (
            "kubectl --context prod get secret db-credentials -o yaml",
            None,
        ),
        ("kubectl get secret db-credentials -o yaml", None),
    ];
    for (command, expected) in cases {
        let mut asked = review(command);
        asked.cwd = Some(home.display().to_string());
        asked.home_dir = Some(home.display().to_string());
        let hint = live_under(&controls, &command_payload(command), &asked, soon());
        let permission_ids = hint.and_then(|hint| hint.get("permission_ids").cloned());
        assert_eq!(&permission_ids, expected, "{command}");
    }
}
