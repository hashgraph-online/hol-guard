use gauntlet_host_state::fixed_live_provider_start_plan;
use serde_json::{json, Value};
use std::path::Path;

fn fixture() -> Value {
    serde_json::from_str(include_str!("python_live_provider_start_v1.json")).unwrap()
}

#[test]
fn fixed_plan_and_bounded_startup_claim_match_python_source() {
    let fixture = fixture();
    let delta: Value =
        serde_json::from_str(include_str!("../../../integration-source-delta.v1.json")).unwrap();
    for (name, path) in [
        ("live_local", "ci/gauntlet/control_plane/live_local.py"),
        (
            "live_provider",
            "ci/gauntlet/control_plane/live_provider.py",
        ),
    ] {
        let entry = delta["changed"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["path"] == path)
            .unwrap();
        assert_eq!(fixture["source_sha256"][name], entry["sha256"]);
    }
    assert_eq!(
        fixture["schema"],
        "hol-gauntlet-python-live-provider-start-fixtures.v1"
    );
    assert_eq!(
        fixture["command_ast_sha256"],
        "cb60a268c9b5d0c7b8bc8265fec6987615826cb103c00af83cfde3e1d74f877f"
    );
    assert_eq!(
        fixture["return_ast_sha256"],
        "b9ad094b3c656d81e416a8a1f4dd02a5068b2baea801de3e9cf563e04633cac1"
    );
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 3);
    for case in cases {
        let plan = fixed_live_provider_start_plan(
            fixture["job_id"].as_str().unwrap(),
            case["profile"].as_str().unwrap(),
            fixture["candidate_source_sha"].as_str().unwrap(),
            Path::new("/reviewed/hol/workflow-benchmark-implementation"),
        )
        .unwrap();
        assert_eq!(plan.to_json(), case["plan"]);
        let observed = plan
            .parse_startup_stdout(
                case["stdout"].as_str().unwrap().as_bytes(),
                fixture["known_tokens_before"].as_u64().unwrap(),
            )
            .unwrap();
        assert_eq!(observed["pid"], case["result"]["pid"]);
        assert_eq!(
            observed["provider_sha256"],
            case["result"]["provider_sha256"]
        );
        assert_eq!(observed["model_sha256"], case["result"]["model_sha256"]);
        assert_eq!(observed["execution_eligible"], false);
        assert_eq!(observed["producer_claim_only"], true);
    }
}

#[test]
fn producer_output_cannot_change_identity_or_quota() {
    let fixture = fixture();
    let case = &fixture["cases"][1];
    let plan = fixed_live_provider_start_plan(
        fixture["job_id"].as_str().unwrap(),
        "feature-ai",
        fixture["candidate_source_sha"].as_str().unwrap(),
        Path::new("/reviewed/hol/workflow-benchmark-implementation"),
    )
    .unwrap();
    assert!(plan.parse_startup_stdout(b"{}", 13_746_906).is_err());
    let extra_blank = format!("{}\n", case["stdout"].as_str().unwrap());
    assert!(plan
        .parse_startup_stdout(extra_blank.as_bytes(), 13_746_906)
        .is_err());
    assert!(plan
        .parse_startup_stdout(b"{\"pid\":1,\"pid\":2}\n", 13_746_906)
        .is_err());
    for (field, replacement) in [
        ("root", json!("/tmp/other")),
        ("provider_manifest", json!("/tmp/other.json")),
        ("model_id", json!("other-model")),
        ("pid", json!(0)),
        ("known_tokens_before", json!(1)),
        ("maximum_accounted_tokens", json!(1)),
        ("provider_sha256", json!("bad")),
    ] {
        let mut value = case["result"].clone();
        value[field] = replacement;
        let stdout = format!("{value}\n");
        assert!(
            plan.parse_startup_stdout(stdout.as_bytes(), 13_746_906)
                .is_err(),
            "{field}"
        );
    }
    let mut extra = case["result"].clone();
    extra["unreviewed"] = json!(true);
    assert!(plan
        .parse_startup_stdout(format!("{extra}\n").as_bytes(), 13_746_906)
        .is_err());
    assert!(fixed_live_provider_start_plan(
        "../bad",
        "feature-ai",
        &"a".repeat(40),
        Path::new("/reviewed/hol/workflow-benchmark-implementation")
    )
    .is_err());
    assert!(fixed_live_provider_start_plan(
        "0123456789abcdef",
        "feature-ai",
        &"a".repeat(40),
        Path::new("/reviewed/hol/other")
    )
    .is_err());
    assert!(fixed_live_provider_start_plan(
        "0123456789abcdef",
        "feature-ai",
        &"a".repeat(40),
        Path::new("/reviewed/hol with space/workflow-benchmark-implementation")
    )
    .is_err());
}
