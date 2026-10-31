use serde_json::json;

use super::*;

const NOW: &str = "2026-10-29T12:00:00+00:00";
const ARTIFACT: &str = "codex:project:package-request:left-pad";

fn exception(fields: Value) -> Value {
    let mut entry = json!({
        "exceptionId": "exception-1",
        "scope": "artifact",
        "harness": "codex",
        "owner": "owner@example.test",
        "expiresAt": "2099-01-01T00:00:00+00:00",
        "artifactId": ARTIFACT,
    });
    for (key, value) in fields.as_object().unwrap() {
        if value.is_null() {
            entry.as_object_mut().unwrap().remove(key);
        } else {
            entry[key] = value.clone();
        }
    }
    entry
}

fn bundle(exceptions: Vec<Value>) -> Map<String, Value> {
    json!({ "workspaceId": "workspace-1", "cloudExceptions": exceptions })
        .as_object()
        .unwrap()
        .clone()
}

fn target<'a>(harness: &'a str, artifact_id: &'a str) -> LiftTarget<'a> {
    LiftTarget {
        harness,
        artifact_id: Some(artifact_id),
        publisher: None,
        workspace: None,
        now: NOW,
    }
}

fn lifted(exceptions: Vec<Value>, target: &LiftTarget<'_>) -> bool {
    cloud_exception_covers(Some(&bundle(exceptions)), target)
}

#[test]
fn an_active_exception_drops_the_bundle_rules_that_restrict() {
    assert!(lifted(
        vec![exception(json!({}))],
        &target("codex", ARTIFACT)
    ));
}

#[test]
fn nothing_lifts_without_a_bundle_or_a_covering_exception() {
    assert!(!cloud_exception_covers(None, &target("codex", ARTIFACT)));
    assert!(!lifted(
        vec![exception(json!({}))],
        &target("codex", "codex:project:other")
    ));
    assert!(!lifted(
        vec![exception(json!({}))],
        &target("claude-code", ARTIFACT)
    ));
}

#[test]
fn an_expired_or_malformed_exception_lifts_nothing() {
    let target = target("codex", ARTIFACT);
    assert!(!lifted(
        vec![exception(
            json!({ "expiresAt": "2026-10-29T11:59:59+00:00" })
        )],
        &target
    ));
    assert!(!lifted(vec![exception(json!({ "owner": null }))], &target));
    assert!(!lifted(
        vec![exception(json!({ "effect": "deny" }))],
        &target
    ));
    assert!(!lifted(
        vec![exception(json!({ "scope": "everything" }))],
        &target
    ));
}

#[test]
fn an_exception_without_a_harness_applies_to_every_harness() {
    let entry = exception(json!({ "harness": null }));
    assert!(lifted(
        vec![entry.clone()],
        &target("claude-code", ARTIFACT)
    ));
    assert!(lifted(
        vec![exception(json!({ "harness": "*" }))],
        &target("claude-code", ARTIFACT)
    ));
}

#[test]
fn an_artifact_exception_must_name_its_artifact() {
    assert!(!lifted(
        vec![exception(json!({ "artifactId": null }))],
        &target("codex", ARTIFACT)
    ));
    let legacy =
        exception(json!({ "artifactId": null, "exceptionId": format!("artifact:{ARTIFACT}") }));
    assert!(lifted(vec![legacy], &target("codex", ARTIFACT)));
}

#[test]
fn every_named_target_narrows_the_exception() {
    let directory = exception(json!({ "workingDirectory": "/repo/a" }));
    let mut in_directory = target("codex", ARTIFACT);
    in_directory.workspace = Some("/repo/a");
    assert!(lifted(vec![directory.clone()], &in_directory));
    in_directory.workspace = Some("/repo/b");
    assert!(!lifted(vec![directory], &in_directory));

    let publisher =
        exception(json!({ "scope": "publisher", "artifactId": null, "publisher": "acme" }));
    let mut by_publisher = target("codex", ARTIFACT);
    by_publisher.publisher = Some("acme");
    assert!(lifted(vec![publisher.clone()], &by_publisher));
    by_publisher.publisher = Some("other");
    assert!(!lifted(vec![publisher.clone()], &by_publisher));
    by_publisher.publisher = None;
    assert!(!lifted(vec![publisher], &by_publisher));
}

#[test]
fn an_exception_for_another_cloud_workspace_lifts_nothing() {
    let target = target("codex", ARTIFACT);
    assert!(!lifted(
        vec![exception(json!({ "workspaceId": "workspace-2" }))],
        &target
    ));
    assert!(lifted(
        vec![exception(json!({ "workspaceId": "workspace-1" }))],
        &target
    ));
}

#[test]
fn the_last_entry_for_an_exception_id_wins() {
    let target = target("codex", ARTIFACT);
    let expired = exception(json!({ "expiresAt": "2026-10-29T11:59:59+00:00" }));
    assert!(!lifted(
        vec![exception(json!({})), expired.clone()],
        &target
    ));
    assert!(lifted(vec![expired, exception(json!({}))], &target));
}
