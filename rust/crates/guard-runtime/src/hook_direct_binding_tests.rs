use super::{allowed_payload, deferred, lane, run, run_as, HOME};
use crate::hook_direct::{evaluate, HookDirectRequestV1};
use crate::policy_store::policy_store_direct_lane::tests::{binding, push};
use crate::policy_store::policy_store_direct_lane::DirectLaneDefer;
use serde_json::{json, Value};
use std::fs;

#[test]
fn request_shapes_the_daemon_must_handle_defer() {
    let lane = lane("shapes", json!({}));
    let mut probe = allowed_payload(&lane);
    probe["guard_transition_probe"] = json!({});
    assert_eq!(deferred(&run(&lane, probe)), "direct_hook_transition_probe");
    let mut reference = allowed_payload(&lane);
    reference["guard_payload_ref"] = json!("ref");
    assert_eq!(
        deferred(&run(&lane, reference)),
        "direct_hook_payload_unsupported"
    );
    // Codex, Copilot, Devin and ZCode PermissionRequest is the no-decision
    // passthrough. A harness without it still defers, and the command is
    // not judged.
    let mut permission = allowed_payload(&lane);
    permission["hook_event_name"] = json!("PermissionRequest");
    assert_eq!(
        deferred(&run_as(&lane, "kimi", Some(HOME), permission)),
        "direct_hook_event_unsupported"
    );
    let mut environment = allowed_payload(&lane);
    environment["guard_execution_environment"] = json!("PATH=/bin");
    assert_eq!(
        deferred(&run(&lane, environment)),
        "direct_hook_execution_environment_invalid"
    );
    let mut homeless = allowed_payload(&lane);
    homeless.as_object_mut().unwrap().remove("cwd");
    assert_eq!(
        deferred(&run(&lane, homeless)),
        "direct_hook_workspace_missing"
    );
    let mut elsewhere = allowed_payload(&lane);
    elsewhere["cwd"] = json!(lane.fixture.root.to_str().unwrap());
    // An overlay keeps the unbound directory waiting for its own publish.
    fs::write(lane.fixture.root.join(".hol-guard.toml"), b"").unwrap();
    assert_eq!(
        deferred(&run(&lane, elsewhere)),
        DirectLaneDefer::WorkspaceUnknown.code()
    );
    assert_eq!(
        deferred(&run(&lane, json!(["not", "an", "object"]))),
        "direct_hook_payload_unsupported"
    );
}

#[test]
fn other_harnesses_and_homes_defer() {
    let lane = lane("harness", json!({}));
    let mut request = HookDirectRequestV1 {
        harness: "gemini".to_owned(),
        guard_home: lane.fixture.root.to_str().unwrap().to_owned(),
        home_dir: Some(HOME.to_owned()),
        workspace: None,
        deadline_budget_ms: None,
        payload: allowed_payload(&lane),
    };
    let result: Value =
        serde_json::from_slice(&evaluate(request.clone(), &lane.fixture.store).unwrap()).unwrap();
    assert_eq!(deferred(&result), "direct_hook_harness_unsupported");
    request.harness = "codex".to_owned();
    request.home_dir = Some("/home/other".to_owned());
    let result: Value =
        serde_json::from_slice(&evaluate(request, &lane.fixture.store).unwrap()).unwrap();
    assert_eq!(deferred(&result), "direct_hook_home_mismatch");
}

#[test]
fn a_binding_without_posture_overrides_still_answers() {
    // `binding_with_harness_postures` leaves the map out when no harness
    // carries an override, which is the common policy. That must read as no
    // override and fall through to the snapshot mode, not as a truncated
    // binding.
    let lane = lane("no-postures", json!({}));
    let mut bound = binding(&lane.fixture, &lane.workspace);
    bound["home_dir"] = json!(HOME);
    bound["local_cli_block_rules"] = json!(false);
    bound["evidence_drain"] = json!(true);
    bound.as_object_mut().unwrap().remove("harness_postures");
    push(&lane.fixture, Some(bound)).unwrap();
    assert_eq!(run(&lane, allowed_payload(&lane))["outcome"], "answer");
}

#[test]
fn daemon_only_state_in_the_binding_defers() {
    // The daemon checks custom rules only against an allow floor, and this
    // fixture policy warns on commands.
    let rules = lane("rules", json!({ "local_cli_block_rules": true }));
    assert_eq!(run(&rules, allowed_payload(&rules))["outcome"], "answer");
    for (label, missing) in [
        ("no-home", "home_dir"),
        ("no-rules", "local_cli_block_rules"),
    ] {
        let lane = lane(label, json!({}));
        let mut bound = binding(&lane.fixture, &lane.workspace);
        bound["home_dir"] = json!(HOME);
        bound["harness_postures"] = json!({});
        bound["local_cli_block_rules"] = json!(false);
        bound["evidence_drain"] = json!(true);
        bound.as_object_mut().unwrap().remove(missing);
        push(&lane.fixture, Some(bound)).unwrap();
        assert_eq!(
            deferred(&run(&lane, allowed_payload(&lane))),
            "direct_hook_binding_incomplete",
            "{missing}"
        );
    }
}
