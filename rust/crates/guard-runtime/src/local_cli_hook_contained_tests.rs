//! A local CLI grant never takes a sandbox-bound action out of the sandbox.

use guard_contracts::LocalCliIdentitySourceV1;
use serde_json::{json, Value};

use super::*;
use crate::local_cli_hook_op::tests::Fixture;
use crate::local_cli_hook_op::{evaluate_local_cli_hook_request, run_refined};

fn outside_roots(fixture: &Fixture, command: &str) -> LocalCliHookRequestV1 {
    let mut request = fixture.request(command, "review", true);
    request.current_reason_code = Some(OUTSIDE_ROOTS_REASON.to_owned());
    request
}

fn synthetic_launch() -> Launch {
    // `refine` never reads the source.
    let source = LocalCliIdentitySourceV1::Script {
        entrypoint: Value::Null,
    };
    Launch {
        cli_id: "local-cli.lanectl".to_owned(),
        identity_hash: "a".repeat(64),
        name: "lanectl".to_owned(),
        kind: "binary".to_owned(),
        runner: None,
        source,
    }
}

#[test]
fn an_allowed_grant_widens_the_sandbox_and_never_allows() {
    let fixture = Fixture::new("contained-allowed");
    let identity = fixture.identity();
    fixture.grant(&identity.cli_id, &identity.identity_hash, "allowed");
    for request in [
        fixture.request("npm run build", "sandbox-required", true),
        outside_roots(&fixture, "npm run build"),
    ] {
        let refined = run_refined(&request).unwrap();
        assert_eq!(refined.action, ALLOW_CONTAINED_WITH_GRANT);
        assert_eq!(refined.connector, None);
        let grant = refined.contained_grant.expect("the grant travels with it");
        assert_eq!(grant["cli_id"], identity.cli_id.as_str());
        assert_eq!(grant["identity_hash"], identity.identity_hash.as_str());
        assert_eq!(grant["capabilities"], json!([]), "absent means none");
        let reply: Value =
            serde_json::from_slice(&evaluate_local_cli_hook_request(&request).unwrap()).unwrap();
        assert_eq!(reply["payload"]["action"], ALLOW_CONTAINED_WITH_GRANT);
        assert_eq!(reply["payload"]["contained_grant"], grant);
    }
    // A generic review keeps today's refinement.
    let generic = run_refined(&fixture.request("npm run build", "review", true)).unwrap();
    assert_eq!(generic.action, "allow");
    assert_eq!(generic.contained_grant, None);
}

#[test]
fn a_blocked_grant_blocks_a_sandbox_bound_action() {
    let fixture = Fixture::new("contained-blocked");
    let identity = fixture.identity();
    fixture.grant(&identity.cli_id, &identity.identity_hash, "blocked");
    for request in [
        fixture.request("npm run build", "sandbox-required", true),
        outside_roots(&fixture, "npm run build"),
    ] {
        let refined = run_refined(&request).unwrap();
        assert_eq!(refined.action, "block");
        assert_eq!(refined.contained_grant, None);
    }
}

#[test]
fn an_unset_grant_keeps_the_sandbox_or_names_the_connector() {
    let fixture = Fixture::new("contained-unset");
    let identity = fixture.identity();
    // A command the sandbox already runs keeps running there.
    let sandboxed =
        run_refined(&fixture.request("npm run build", "sandbox-required", true)).unwrap();
    assert_eq!(sandboxed.action, "sandbox-required");
    assert_eq!(sandboxed.connector, None);
    // One it could not run waits on the connector setup.
    let outside = run_refined(&outside_roots(&fixture, "npm run build")).unwrap();
    assert_eq!(outside.action, "review");
    let connector = outside.connector.expect("an unset CLI names its connector");
    assert_eq!(connector["identity_hash"], identity.identity_hash.as_str());
    assert_eq!(outside.contained_grant, None);
}

#[test]
fn an_untrusted_answer_keeps_a_sandbox_bound_action() {
    let fixture = Fixture::new("contained-unverified");
    fixture
        .connection
        .execute("update local_cli_schema_migration set version = 99", [])
        .unwrap();
    fixture.grant("local-cli.other", &"0".repeat(64), "blocked");
    for request in [
        fixture.request("npm run build", "sandbox-required", true),
        outside_roots(&fixture, "npm run build"),
    ] {
        let refined = run_refined(&request).unwrap();
        assert_eq!(refined.action, request.current_action);
        assert_eq!(refined.contained_grant, None);
    }
    // Grant lookups off leave every action alone.
    let off = fixture.request("npm run build", "sandbox-required", false);
    assert_eq!(run_refined(&off).unwrap().action, "sandbox-required");
}

#[test]
fn only_known_sorted_distinct_capabilities_are_trusted() {
    assert_eq!(grant_capabilities(&Value::Null), Ok(Vec::new()));
    assert_eq!(
        grant_capabilities(&json!(GRANT_CAPABILITIES)),
        Ok(GRANT_CAPABILITIES.map(str::to_owned).to_vec())
    );
    for value in [
        json!(["network"]),
        json!(["state-dir-read", "loopback-network"]),
        json!(["loopback-network", "loopback-network"]),
        json!([1]),
        json!("loopback-network"),
        json!({}),
    ] {
        assert_eq!(grant_capabilities(&value), Err(()), "{value}");
    }
}

#[test]
fn refine_never_turns_a_sandbox_requirement_into_allow() {
    let fixture = Fixture::new("contained-refine");
    let request = fixture.request("lanectl status", "sandbox-required", true);
    let allowed = |capabilities: Value| -> Answer {
        Ok((Some("allowed"), Some(synthetic_launch()), capabilities))
    };
    let refined = refine(&request, allowed(json!(["loopback-network"])), || {
        "allow".to_owned()
    });
    assert_eq!(refined.action, ALLOW_CONTAINED_WITH_GRANT);
    assert_eq!(
        refined.contained_grant.unwrap()["capabilities"],
        json!(["loopback-network"])
    );
    // An unknown capability is not a trustworthy grant.
    let unknown = refine(&request, allowed(json!(["network"])), || "allow".to_owned());
    assert_eq!(unknown, Refined::keep(&request));
    for answer in [
        Err(()),
        Ok((Some("allowed"), None, Value::Null)),
        Ok((None, None, Value::Null)),
        Ok((None, Some(synthetic_launch()), Value::Null)),
    ] {
        let refined = refine(&request, answer, || "allow".to_owned());
        assert_eq!(refined.action, "sandbox-required");
    }
    assert!(!refinable(&fixture.request(
        "lanectl status",
        "block",
        true
    )));
    assert!(refinable(&fixture.request(
        "lanectl status",
        "sandbox-required",
        true
    )));
}
